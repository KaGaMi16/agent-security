"""kgm-agent-security 扫描器的共享工具。

约束：只读、无网络、不执行被扫描内容。所有输出会脱敏常见密钥形态。
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_LABEL = {
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

REDACT_RE = re.compile(
    r"(?i)("
    r"sk-[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}"
    r"|github_pat_[A-Za-z0-9_]{8,}"
    r"|xox[baprs]-[A-Za-z0-9-]{8,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
    r")"
)

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x034F: "COMBINING GRAPHEME JOINER",
}

# 指令/配置文件中出现即需人工复核的模式。这些是"复核信号"，不是自动定罪。
INJECTION_RULES = [
    (
        "INJ_IGNORE_INSTRUCTIONS",
        "high",
        "要求忽略既有指令或规则",
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b[^\n]{0,40}\b(previous|prior|above|earlier)\b[^\n]{0,24}\b(instructions?|prompts?|rules?|system)\b"
            r"|(忽略|无视|忘记)[^\n]{0,12}(之前的|以上的|先前的|系统)?[^\n]{0,12}(指令|提示|规则|要求)"
        ),
    ),
    (
        "INJ_HIDE_FROM_USER",
        "high",
        "要求对用户/操作者隐瞒行为",
        re.compile(
            r"(?i)\b(do\s+not|don'?t|never)\s+(tell|inform|notify|mention)\b[^\n]{0,30}\b(user|operator|human|owner)\b"
            r"|(不要|不得|别)[^\n]{0,10}(告诉|告知|通知|提醒)[^\n]{0,10}(用户|使用者|操作者)"
            r"|(瞒着|隐瞒)[^\n]{0,10}(用户|操作者)"
        ),
    ),
    (
        "INJ_EXFIL",
        "high",
        "疑似外传凭据或数据",
        re.compile(
            r"(?i)(exfiltrat\w*|send\b[^\n]{0,60}\b(token|credential|secret|ssh|\.env|api[_-]?key|config)\b[^\n]{0,40}(https?://|webhook|pastebin|ngrok|transfer\.sh|requestbin))"
        ),
    ),
    (
        "INJ_PIPE_SHELL",
        "high",
        "下载内容直接管道给 shell 执行",
        re.compile(
            r"(?i)\b(curl|wget)\b[^\n]{0,180}\|\s*(sudo\s+)?(ba|z|k)?sh\b"
            r"|(ba|z|k)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)"
        ),
    ),
    (
        "INJ_BASE64_EXEC",
        "medium",
        "base64 解码后执行或落盘",
        re.compile(
            r"(?i)base64\s+(-d|-D|--decode)[^\n]{0,100}(\|\s*(ba|z|k)?sh|\bto\b[^\n]{0,20}\.(sh|js|py)\b|>\s*\S+\.(sh|js|py))"
        ),
    ),
    (
        "INJ_CONFIG_WRITE",
        "medium",
        "指示修改 agent / 工具配置（持久化路径）",
        re.compile(
            r"(?i)(config\.toml|settings\.json|settings\.local\.json|\.mcp\.json|managed-settings\.json)"
            r"[^\n]{0,100}(write|append|add|modify|set|更新|写入|追加|修改)"
            r"|(write|append|add|modify|set|更新|写入|追加|修改)[^\n]{0,100}(config\.toml|settings\.json|\.mcp\.json|managed-settings\.json)"
        ),
    ),
    (
        "INJ_DISABLE_GUARD",
        "medium",
        "指示绕过审批、沙箱或权限确认",
        re.compile(
            r"(?i)(dangerously[-_]?(bypass|disable)[a-z-]*|--yolo\b|bypassPermissions|danger-full-access"
            r"|skip[-_]?permissions|dangerouslyDisableSandbox|approval[_-]?policy\s*=\s*[\"']?never"
            r"|approvals\.mode\s*[:=]\s*[\"']?off)"
        ),
    ),
    (
        "INJ_PROXY_HIJACK",
        "medium",
        "改走非官方模型网关或代理（凭据可被中间人截获）",
        re.compile(
            r"(?i)\b(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|CHATGPT_BASE_URL)\b"
        ),
    ),
    (
        "INJ_TMP_INSTALL",
        "medium",
        "在临时目录安装/执行包",
        re.compile(
            r"(?i)(/tmp/|/private/tmp/|%TEMP%\\|\\Temp\\)[^\n]{0,140}(npm|pnpm|yarn|pip|npx|install|node|python|\.sh\b)"
        ),
    ),
    (
        "INJ_PERSIST",
        "low",
        "涉及开机/登录持久化机制",
        re.compile(
            r"(?i)\b(launchctl\s+submit|crontab\s+-|LaunchAgents|LaunchDaemons|systemctl\s+--user\s+enable|\.zshrc|\.bash_profile|authorized_keys)\b"
        ),
    ),
]

# 命令/参数中出现即高度可疑（后利用与持久化特征）。
SUSPICIOUS_COMMAND_TOKENS = [
    (r"/tmp/|/private/tmp/|%TEMP%\\", "使用临时目录路径"),
    (r"\blaunchctl\b", "使用 launchctl 持久化"),
    (r"\b(base64|xxd)\b[^\n]{0,20}(-d|-D|--decode)", "base64 解码"),
    (r"\|\s*(sudo\s+)?(ba|z|k)?sh\b", "管道到 shell"),
    (r"\b(curl|wget)\b", "下载器"),
    (r"\b(npm|pnpm|yarn)\s+(install|i|add)\b", "安装 npm 包"),
    (r"\bnpx\b", "npx 远程执行"),
    (r"\bnode\s+(-e|--eval)\b", "node 内联执行"),
    (r"\bpython[0-9.]*\s+-c\b", "python 内联执行"),
    (r"\bosascript\b", "AppleScript 执行"),
    (r"/dev/tcp/", "反弹 shell 特征"),
    (r"\beval\b", "eval 动态执行"),
]

STANDARD_BIN_PREFIXES = (
    "/Applications/",
    "/usr/bin/",
    "/usr/local/bin/",
    "/usr/local/",
    "/opt/homebrew/",
    "/opt/",
    "/bin/",
    "/sbin/",
    "/System/",
)

OFFICIAL_MODEL_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "generativelanguage.googleapis.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
)


@dataclass
class Finding:
    id: str
    severity: str
    area: str
    path: str
    evidence: str
    why: str
    action: str

    def to_dict(self) -> dict:
        return asdict(self)


def add(
    findings: list,
    fid: str,
    severity: str,
    area: str,
    path: os.PathLike | str,
    evidence: str,
    why: str,
    action: str,
) -> None:
    findings.append(
        Finding(
            id=fid,
            severity=severity,
            area=area,
            path=str(path),
            evidence=redact(evidence),
            why=why,
            action=action,
        )
    )


def redact(text: object, limit: int = 220) -> str:
    value = " ".join(str(text).split())
    value = REDACT_RE.sub("<redacted>", value)
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    return value


def unicode_anomalies(text: str, max_items: int = 20) -> list[dict]:
    """返回零宽/双向控制/标签字符的位置（用于隐藏 prompt 检测）。"""
    results: list[dict] = []
    line = 1
    for pos, ch in enumerate(text):
        code = ord(ch)
        if ch == "\n":
            line += 1
            continue
        name = ZERO_WIDTH.get(code)
        if name is None and 0xE0000 <= code <= 0xE007F:
            name = "UNICODE TAG CHARACTER"
        if name is None:
            continue
        results.append(
            {
                "offset": pos,
                "line": line,
                "codepoint": f"U+{code:04X}",
                "name": name,
            }
        )
        if len(results) >= max_items:
            break
    return results


def scan_injection(text: str, max_per_rule: int = 5) -> list[dict]:
    """按行扫描提示注入与持久化模式，返回命中详情。"""
    hits: list[dict] = []
    counts: dict[str, int] = {}
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        for rule_id, severity, label, pattern in INJECTION_RULES:
            if counts.get(rule_id, 0) >= max_per_rule:
                continue
            match = pattern.search(line)
            if not match:
                continue
            counts[rule_id] = counts.get(rule_id, 0) + 1
            start = max(0, match.start() - 40)
            end = min(len(line), match.end() + 40)
            hits.append(
                {
                    "rule": rule_id,
                    "severity": severity,
                    "label": label,
                    "line": line_no,
                    "snippet": redact(line[start:end]),
                }
            )
    return hits


def suspicious_command(text: str) -> list[str]:
    reasons = []
    for pattern, label in SUSPICIOUS_COMMAND_TOKENS:
        if re.search(pattern, text, re.IGNORECASE):
            reasons.append(label)
    return reasons


def is_probably_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / max(1, len(sample)) < 0.75


def read_text_limited(path: os.PathLike | str, max_bytes: int = 1_500_000) -> Optional[str]:
    """只读打开文本文件；超限或二进制返回 None。"""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            if is_probably_binary(handle.read(4096)):
                return None
            handle.seek(0)
            data = handle.read(max_bytes)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def summarize(findings: list[Finding]) -> dict:
    counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "total": len(findings),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
    }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.area, f.path, f.id),
    )


def emit(findings: list[Finding], output_format: str, title: str) -> None:
    findings = sort_findings(findings)
    summary = summarize(findings)
    if output_format == "json":
        print(
            json.dumps(
                {"title": title, "summary": summary, "findings": [f.to_dict() for f in findings]},
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    print(f"# {title}")
    print(
        "汇总：高危 {high} · 中危 {medium} · 低危 {low} · 提示 {info}（共 {total}）".format(
            **summary
        )
    )
    if not findings:
        print("\n未发现明显异常。注意：没有告警不等于安全，详见 SKILL.md「误判与局限」。")
        return
    print()
    for finding in findings:
        print(f"[{SEVERITY_LABEL.get(finding.severity, finding.severity)}] {finding.id} · {finding.area}")
        print(f"  位置：{finding.path}")
        print(f"  证据：{finding.evidence}")
        print(f"  原因：{finding.why}")
        print(f"  建议：{finding.action}")
        print()


def fail_on_exit_code(findings: list[Finding], fail_on: str) -> int:
    threshold = SEVERITY_ORDER.get(fail_on, 3)
    worst = max((SEVERITY_ORDER.get(f.severity, 0) for f in findings), default=0)
    return 1 if worst >= threshold else 0
