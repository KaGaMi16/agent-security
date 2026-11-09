"""verify_external_skills.py 的只读自测。

运行：python3 -m unittest discover -s tests -v
全部使用临时目录；不读写真实用户配置。
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import verify_external_skills as verifier  # noqa: E402


class ExternalSkillsVerifierTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "workspace"
        self.overlay = self.root / "control/machine-local/external-skills/skills"
        self.skill = self.overlay / "demo-skill"
        self.skill.mkdir(parents=True)
        (self.skill / "SKILL.md").write_text("---\nname: demo-skill\n---\n", encoding="utf-8")
        (self.skill / "scripts").mkdir()
        (self.skill / "scripts/run.py").write_text("print('ok')\n", encoding="utf-8")
        self.spec_path = self.root / "control/base/external-skills.json"
        self.spec_path.parent.mkdir(parents=True)
        self.receipt_path = self.root / "control/machine-local/external-skills/receipt.json"
        self._write_clean()

    def _write_clean(self):
        packages = [
            {
                "name": "demo-package",
                "source": "https://example.invalid/demo.git",
                "ref": "0123456789abcdef",
                "activeSkillNames": ["demo-skill"],
                "skillSourceMap": {"demo-skill": "skills/demo-skill"},
            }
        ]
        fingerprints = {"demo-skill": verifier.tree_fingerprint(self.skill)}
        self.spec = {
            "version": 1,
            "packages": packages,
            "expectedSkillFingerprints": fingerprints,
        }
        self.spec_path.write_text(json.dumps(self.spec, indent=2) + "\n", encoding="utf-8")
        self.receipt = {
            "specSha256": verifier.sha256_file(self.spec_path),
            "packages": packages,
            "skills": dict(fingerprints),
        }
        self.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        self.receipt_path.write_text(json.dumps(self.receipt, indent=2) + "\n", encoding="utf-8")

    def _verify(self, hosts=None):
        return verifier.verify_external_skills(self.root, hosts=hosts)

    def _ids(self, findings):
        return {finding.id for finding in findings}

    def _worst(self, findings):
        return max((verifier.SEVERITY_ORDER[finding.severity] for finding in findings), default=0)

    def test_clean_overlay_has_no_problem_findings(self):
        findings = self._verify(hosts=[])
        self.assertIn("EXT_VERIFIED", self._ids(findings))
        self.assertEqual(self._worst(findings), verifier.SEVERITY_ORDER["info"])

    def test_tampered_skill_content_is_high(self):
        (self.skill / "scripts/run.py").write_text("print('tampered')\n", encoding="utf-8")
        findings = self._verify(hosts=[])
        self.assertIn("EXT_FP_MISMATCH", self._ids(findings))
        self.assertEqual(self._worst(findings), verifier.SEVERITY_ORDER["high"])

    def test_receipt_bound_to_old_spec_is_high(self):
        self.spec["version"] = 2
        self.spec_path.write_text(json.dumps(self.spec, indent=2) + "\n", encoding="utf-8")
        findings = self._verify(hosts=[])
        self.assertIn("EXT_RECEIPT_SPEC_SHA", self._ids(findings))

    def test_extra_installed_skill_is_high(self):
        extra = self.overlay / "stale-skill"
        extra.mkdir()
        (extra / "SKILL.md").write_text("stale\n", encoding="utf-8")
        findings = self._verify(hosts=[])
        self.assertIn("EXT_OVERLAY_ROSTER", self._ids(findings))
        self.assertIn("EXT_UNDECLARED_SKILL", self._ids(findings))

    def test_missing_installed_skill_is_high(self):
        import shutil

        shutil.rmtree(self.skill)
        findings = self._verify(hosts=[])
        self.assertIn("EXT_SKILL_MISSING", self._ids(findings))

    def test_dangling_host_link_is_medium(self):
        hostdir = Path(self._tmp.name) / "host-skills"
        hostdir.mkdir()
        (hostdir / "gone").symlink_to(Path(self._tmp.name) / "missing-target")
        findings = self._verify(hosts=[("demo-host", str(hostdir))])
        self.assertIn("HOST_LINK_DANGLING", self._ids(findings))


if __name__ == "__main__":
    unittest.main()
