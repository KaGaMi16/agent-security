#!/usr/bin/env python3
"""Verify pinned third-party skill overlays against their authority spec (read-only).

Checks:
  1. authority spec parses and contains packages + expectedSkillFingerprints;
  2. materialized receipt is bound to the current spec (specSha256);
  3. receipt package list matches the spec;
  4. receipt skill roster matches the spec fingerprint roster;
  5. every installed skill directory matches its expected directory fingerprint;
  6. optional: host skill symlinks resolve inside the workspace and point at known skills.

No writes, no network, no command execution. Exit code is driven by --fail-on.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    SEVERITY_ORDER,
    Finding,
    add,
    emit,
    fail_on_exit_code,
    summarize,
)

DEFAULT_HOSTS = [
    ("agents", "~/.agents/skills"),
    ("codex", "~/.codex/skills"),
    ("claude", "~/.claude/skills"),
    ("hermes", "~/.hermes/skills"),
]


def tree_fingerprint(root: Path) -> str:
    """Content fingerprint used by control/content/tools/download-external-skills.py."""
    value = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root)).encode("utf-8", "surrogateescape")
        value.update(rel + b"\0")
        if path.is_symlink():
            value.update(b"symlink\0" + os.readlink(path).encode("utf-8", "surrogateescape"))
        elif path.is_file():
            value.update(b"file\0" + path.read_bytes())
        elif path.is_dir():
            value.update(b"dir\0")
        value.update(b"\0")
    return value.hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(findings: list[Finding], path: Path, label: str, fid: str) -> dict | None:
    if not path.is_file():
        add(findings, fid + "_MISSING", "high", "external-overlay", path,
            "文件不存在", f"{label} 缺失，无法验证第三方技能来源与内容。",
            "先确认仓库根路径，再按团队安装流程重新生成该文件。")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        add(findings, fid + "_INVALID", "high", "external-overlay", path,
            f"解析失败: {exc}", f"{label} 不是合法 JSON，完整性验证无法进行。",
            "从备份恢复该文件，或重新运行外部技能安装脚本生成。")
        return None


def normalize_packages(packages: list) -> list[dict]:
    out = []
    for item in packages or []:
        if not isinstance(item, dict):
            continue
        entry = {
            "name": str(item.get("name", "")),
            "source": str(item.get("source", "")),
            "ref": str(item.get("ref", "")),
        }
        legacy = item.get("legacyRef") or (item.get("legacySkills") or {}).get("ref")
        if legacy:
            entry["legacyRef"] = str(legacy)
        out.append(entry)
    return out


def expected_skill_names(packages: list) -> list[str]:
    names: list[str] = []
    for item in packages or []:
        if not isinstance(item, dict):
            continue
        names.extend((item.get("skillSourceMap") or {}).keys())
        if not item.get("skillSourceMap"):
            names.extend(item.get("activeSkillNames") or [])
        names.extend(((item.get("legacySkills") or {}).get("paths") or {}).keys())
    return sorted(set(names))


def verify_host_links(
    findings: list[Finding], hosts: list[tuple[str, str]], workspace: Path
) -> None:
    for label, raw in hosts:
        root = Path(os.path.expanduser(raw))
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir(), key=lambda p: p.name):
            if not entry.is_symlink():
                continue
            target = entry.resolve()
            if not target.exists():
                add(findings, "HOST_LINK_DANGLING", "medium", "host-wiring", entry,
                    f"软链指向不存在: {os.readlink(entry)}",
                    f"{label} 宿主技能目录存在断链，可能指向已删除或迁移的外部技能。",
                    "确认该技能是否仍需要；删除断链或重建正确软链。")
                continue
            if not target.is_relative_to(workspace):
                add(findings, "HOST_LINK_OUTSIDE", "low", "host-wiring", entry,
                    f"目标在 workspace 之外: {target}",
                    "宿主技能来自 workspace 之外的目录，内容不受本仓指纹清单管理。",
                    "确认来源；如属第三方技能，纳入 external-skills.json 管理。")


def verify_external_skills(
    workspace: Path,
    spec_path: Path | None = None,
    receipt_path: Path | None = None,
    overlay_dir: Path | None = None,
    hosts: list[tuple[str, str]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    spec_path = spec_path or workspace / "control/base/external-skills.json"
    receipt_path = receipt_path or workspace / "control/machine-local/external-skills/receipt.json"
    overlay_dir = overlay_dir or workspace / "control/machine-local/external-skills/skills"

    spec = load_json(findings, spec_path, "authority spec", "EXT_SPEC")
    receipt = load_json(findings, receipt_path, "overlay receipt", "EXT_RECEIPT")
    if spec is None or receipt is None:
        return findings

    expected = spec.get("expectedSkillFingerprints")
    packages = spec.get("packages")
    if not isinstance(expected, dict) or not expected:
        add(findings, "EXT_SPEC_FINGERPRINTS", "high", "external-overlay", spec_path,
            "expectedSkillFingerprints 缺失或为空",
            "没有指纹清单就无法判断已安装外部技能是否与固定版本一致。",
            "用安装脚本重新生成 spec 指纹，并核对新增包的 ref 与内容。")
        expected = {}
    if not isinstance(packages, list) or not packages:
        add(findings, "EXT_SPEC_PACKAGES", "high", "external-overlay", spec_path,
            "packages 缺失或为空", "无法验证第三方技能的来源与固定版本。",
            "按 external-skills.json 模式声明每个包的 source 与 ref。")

    spec_names = expected_skill_names(packages)
    spec_fp_names = sorted(expected)
    if spec_names != spec_fp_names:
        missing = sorted(set(spec_names) - set(spec_fp_names))
        extra = sorted(set(spec_fp_names) - set(spec_names))
        add(findings, "EXT_SPEC_ROSTER", "medium", "external-overlay", spec_path,
            f"包声明技能 {len(spec_names)} 个，指纹 {len(spec_fp_names)} 个；缺 {missing[:5]} 多 {extra[:5]}",
            "包声明与指纹清单不一致，说明新增/删除技能后未同步更新清单。",
            "补齐或移除对应指纹，然后重新生成 receipt。")

    actual_names: list[str] = []
    if overlay_dir.is_dir():
        actual_names = sorted(p.name for p in overlay_dir.iterdir() if p.is_dir() and not p.is_symlink())

    expected_spec_sha = sha256_file(spec_path)
    if receipt.get("specSha256") != expected_spec_sha:
        add(findings, "EXT_RECEIPT_SPEC_SHA", "high", "external-overlay", receipt_path,
            f"receipt.specSha256={str(receipt.get('specSha256'))[:12]}，当前 spec={expected_spec_sha[:12]}",
            "receipt 绑定的授权文件已被修改，当前安装物不再由该 receipt 背书。",
            "确认 spec 改动来源后重新运行外部技能安装脚本，生成新 receipt。")

    receipt_packages = normalize_packages(receipt.get("packages") or [])
    spec_packages = normalize_packages(packages)
    if receipt_packages != spec_packages:
        add(findings, "EXT_PACKAGE_MISMATCH", "high", "external-overlay", receipt_path,
            f"receipt 包 {len(receipt_packages)} 个，spec 包 {len(spec_packages)} 个，内容不一致",
            "receipt 与 spec 的来源/ref 不一致，无法证明安装物来自固定上游版本。",
            "以 spec 为准重新 materialize，不要手工改 receipt。")

    receipt_skills = receipt.get("skills") or {}
    if sorted(receipt_skills) != sorted(expected):
        add(findings, "EXT_RECEIPT_ROSTER", "high", "external-overlay", receipt_path,
            f"receipt 技能 {len(receipt_skills)} 个，spec 指纹 {len(expected)} 个",
            "receipt 的技能清单与 spec 不一致。", "重新运行安装脚本生成 receipt。")

    if actual_names and actual_names != sorted(expected):
        add(findings, "EXT_OVERLAY_ROSTER", "high", "external-overlay", overlay_dir,
            f"overlay 目录 {len(actual_names)} 个，spec 指纹 {len(expected)} 个",
            "已安装目录与授权清单不一致，可能残留旧版本或混入未声明技能。",
            "按 spec 重新 materialize，并确认残留目录是否应删除。")

    checked = 0
    for name, fingerprint in sorted(expected.items()):
        skill_dir = overlay_dir / name
        if not skill_dir.is_dir():
            add(findings, "EXT_SKILL_MISSING", "high", "external-overlay", skill_dir,
                "目录不存在", f"清单内的第三方技能 {name} 未安装。",
                "运行外部技能安装脚本补齐，或从 spec 中移除该技能。")
            continue
        checked += 1
        actual = tree_fingerprint(skill_dir)
        if actual != fingerprint:
            add(findings, "EXT_FP_MISMATCH", "high", "external-overlay", skill_dir,
                f"实际 {actual[:16]}… 期望 {str(fingerprint)[:16]}…",
                f"{name} 的内容与固定版本不一致，可能被修改、升级或替换。",
                "停止使用该技能；对照上游 diff 或从 spec 固定版本重新下载后再使用。")

    for name in sorted(set(actual_names) - set(expected)):
        add(findings, "EXT_UNDECLARED_SKILL", "high", "external-overlay", overlay_dir / name,
            "目录不在 spec 指纹清单中", f"{name} 是未声明技能，来源与内容都不受清单管理。",
            "确认来源；需要保留则加入 spec 与指纹，否则删除并重新 materialize。")

    if hosts:
        verify_host_links(findings, hosts, workspace)

    add(findings, "EXT_VERIFIED", "info", "external-overlay", overlay_dir,
        f"已核对 {checked}/{len(expected)} 个技能目录；receipt 与 spec 绑定关系见上",
        "info 仅作汇总，不代表其他检查项全部通过。",
        "按 high/medium 项逐条处置。")
    return findings


def find_workspace(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("KGM_AGENT_WORKSPACE")
    if env:
        return Path(env).expanduser().resolve()
    for parent in Path(__file__).resolve().parents:
        if (parent / "control/base/external-skills.json").is_file():
            return parent
    return Path.home() / "kgm-agent-workspace"


def main() -> int:
    parser = argparse.ArgumentParser(description="只读验证第三方技能固定版本与指纹")
    parser.add_argument("--workspace", help="仓库根；默认从脚本位置向上查找，或 KGM_AGENT_WORKSPACE")
    parser.add_argument("--spec", help="覆盖 external-skills.json 路径")
    parser.add_argument("--receipt", help="覆盖 receipt.json 路径")
    parser.add_argument("--overlay", help="覆盖 materialized skills 目录路径")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["high", "medium", "low"], default="high")
    parser.add_argument("--no-hosts", action="store_true", help="跳过宿主软链检查")
    args = parser.parse_args()

    workspace = find_workspace(args.workspace)
    hosts = None if args.no_hosts else DEFAULT_HOSTS
    findings = verify_external_skills(
        workspace,
        spec_path=Path(args.spec).expanduser() if args.spec else None,
        receipt_path=Path(args.receipt).expanduser() if args.receipt else None,
        overlay_dir=Path(args.overlay).expanduser() if args.overlay else None,
        hosts=hosts,
    )
    emit(findings, args.format, "第三方技能完整性与宿主接线核验")
    return fail_on_exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
