#!/usr/bin/env python3
"""多宿主 Agent 信息安全只读自检。

只做三件事：读文件、读配置、汇总分级。不联网、不执行被扫描内容、不写任何文件。
疑似失陷时先按 references/incident-response.md 保留证据，再清理。
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    OFFICIAL_MODEL_HOSTS,
    STANDARD_BIN_PREFIXES,
    add,
    emit,
    fail_on_exit_code,
    read_text_limited,
    redact,
    scan_injection,
    suspicious_command,
    unicode_anomalies,
)

IOC_PACKAGES = ("function-color", "function-flag")
IOC_PATH_PATTERNS = ("ptools",)
INSTRUCTION_NAMES = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", "COPILOT.md")
UNTRUSTED_DIR_HINTS = ("downloads", "desktop", "tmp", "temp", "node_modules", ".cache")

BASE_URL_ENV_RE = re.compile(
    r"(?i)\b(ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|OPENAI_BASE_URL|OPENAI_API_BASE|"
    r"CHATGPT_BASE_URL|GEMINI_API_BASE)\b\s*[:=]\s*[\"']?(https?://[^\s\"',]+)"
)
BASE_URL_KEY_RE = re.compile(
    r"(?i)\b(base_url|baseURL)\b\s*[:=]\s*[\"']?(https?://[^\s\"',]+)"
)


def _is_home_subpath(path: Path, home: Path) -> bool:
    try:
        path.resolve().relative_to(home.resolve())
        return True
    except (OSError, ValueError):
        return False


def _looks_untrusted_location(path: Path) -> bool:
    lowered = str(path).lower()
    return any(hint in lowered for hint in UNTRUSTED_DIR_HINTS)


def _url_host(url: str) -> str:
    match = re.match(r"(?i)^https?://([^/:?#]+)", url)
    return (match.group(1) if match else "").lower()


def _host_official(host: str) -> bool:
    return any(host == official or host.endswith("." + official) for official in OFFICIAL_MODEL_HOSTS)


def _check_base_url(url: str, source: str, path: Path) -> list:
    findings: list = []
    host = _url_host(url)
    if not host or _host_official(host):
        return findings
    add(
        findings,
        "MODEL_GATEWAY_OVERRIDE",
        "high",
        "凭据劫持面",
        path,
        f"{source} -> {url}",
        "模型网关被改到非官方地址，OAuth/API 凭据可能经过第三方，也能被伪造模型返回恶意工具调用。",
        "核对是否为你主动配置的网关；不是则删除该配置并立即轮换对应 token。",
    )
    return findings


# ---------------------------------------------------------------------------
# 指令文件（agent 入口目录 / 当前目录）
# ---------------------------------------------------------------------------


def scan_instruction_files(home: Path, cwd: Path) -> list:
    findings: list = []
    entry_targets = [
        ("agent 入口目录（下载）", home / "Downloads"),
        ("agent 入口目录（桌面）", home / "Desktop"),
        ("临时目录", Path("/tmp")),
    ]
    for label, base in entry_targets:
        if not base.is_dir():
            continue
        for name in INSTRUCTION_NAMES:
            candidate = base / name
            if not candidate.is_file():
                continue
            text = read_text_limited(candidate)
            mtime = datetime.fromtimestamp(candidate.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            add(
                findings,
                "INSTRUCTION_IN_AGENT_ENTRY",
                "medium",
                "指令投毒面",
                candidate,
                f"{label}内存在会被 agent 自动加载的 {name}（mtime {mtime}）",
                "在下载/桌面/临时目录启动 agent 时，这类文件会作为指令进入上下文；文件内容不可信时等价于让模型执行陌生人的命令。",
                "启动任何 agent 前先审阅或移走该文件；不要在下载/桌面/临时目录直接启动 agent。",
            )
            if not text:
                continue
            anomalies = unicode_anomalies(text)
            if anomalies:
                sample = "、".join(f"{item['codepoint']}@{item['line']}行" for item in anomalies[:5])
                add(
                    findings,
                    "HIDDEN_UNICODE",
                    "high",
                    "指令投毒面",
                    candidate,
                    f"发现 {len(anomalies)} 个零宽/双向控制字符：{sample}",
                    "零宽或双向控制字符可用于隐藏 prompt，人眼阅读时看起来是普通文本。",
                    "按原始字节审查该文件；无法解释来源时按已投毒处理，见 references/incident-response.md。",
                )
            for hit in scan_injection(text):
                severity = "high" if hit["severity"] == "high" else "medium"
                add(
                    findings,
                    f"INJECTION/{hit['rule']}",
                    severity,
                    "指令投毒面",
                    candidate,
                    f"{hit['line']}行：{hit['snippet']}",
                    hit["label"],
                    "该文件不在你的可信来源内时，不要在当前主机按其指示执行；先只读审阅并核对来源。",
                )
    # 当前工作目录：只报高信号项，避免把正常项目规则当告警。
    for name in INSTRUCTION_NAMES:
        candidate = cwd / name
        if not candidate.is_file():
            continue
        text = read_text_limited(candidate)
        if not text:
            continue
        anomalies = unicode_anomalies(text)
        if anomalies:
            add(
                findings,
                "HIDDEN_UNICODE",
                "high",
                "指令投毒面",
                candidate,
                f"当前目录的 {name} 含 {len(anomalies)} 个零宽/双向控制字符",
                "正常项目规则不需要这类字符；可能是隐藏 prompt。",
                "核对文件来源与 git 历史；必要时只读渲染后检查。",
            )
        for hit in scan_injection(text):
            if hit["severity"] != "high":
                continue
            add(
                findings,
                f"INJECTION/{hit['rule']}",
                "high",
                "指令投毒面",
                candidate,
                f"{hit['line']}行：{hit['snippet']}",
                hit["label"],
                "当前目录来自陌生仓库/压缩包时，不要按该文件执行动作；先核对其来源与 git 历史。",
            )
    return findings


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------


def _parse_toml_sections(text: str) -> list:
    sections: list = []
    current = {"name": "", "lines": []}
    sections.append(current)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^\[\[?(.+?)\]\]?$", line)
        if match:
            current = {"name": match.group(1).strip(), "lines": []}
            sections.append(current)
            continue
        current["lines"].append(raw)
    return sections


def _section_values(section: dict) -> dict:
    values: dict = {}
    lines = section["lines"]
    index = 0
    while index < len(lines):
        raw = lines[index].strip()
        index += 1
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip().strip('"')
        value = value.strip()
        if value.startswith("[") and "]" not in value:
            collected = [value]
            while index < len(lines):
                collected.append(lines[index].strip())
                index += 1
                if "]" in collected[-1]:
                    break
            value = " ".join(collected)
        values[key] = value.strip().strip('"').strip("'")
    return values


def scan_codex(home: Path) -> list:
    findings: list = []
    config = home / ".codex" / "config.toml"
    if not config.is_file():
        return findings
    text = read_text_limited(config, max_bytes=2_000_000)
    if not text:
        return findings

    if re.search(r'(?m)^\s*approval_policy\s*=\s*"never"', text):
        add(
            findings,
            "CODEX_APPROVALS_NEVER",
            "medium",
            "宿主姿态",
            config,
            'approval_policy = "never"',
            "所有需要确认的动作都不再询问；一旦上下文被注入，破坏性动作可直接发生。",
            "非隔离环境改回 on-request；仅在一次性只读任务里临时使用。",
        )
    if re.search(r'(?m)^\s*sandbox_mode\s*=\s*"danger-full-access"', text):
        add(
            findings,
            "CODEX_FULL_ACCESS",
            "medium",
            "宿主姿态",
            config,
            'sandbox_mode = "danger-full-access"',
            "关闭沙箱并开放网络，直接扩大被投毒后的影响面。",
            "默认使用 workspace-write 或 read-only；不要在陌生目录用 danger-full-access。",
        )
    if re.search(r'(?m)^\s*web_search\s*=\s*"live"', text):
        add(
            findings,
            "CODEX_LIVE_WEB_SEARCH",
            "low",
            "宿主姿态",
            config,
            'web_search = "live"',
            "实时网页内容更容易带入 prompt injection；官方默认是 cached。",
            "除非确需实时检索，改回 cached；把网页结果当作不可信数据。",
        )
    if re.search(r"(?m)^\s*allow_login_shell\s*=\s*true", text):
        add(
            findings,
            "CODEX_LOGIN_SHELL",
            "low",
            "宿主姿态",
            config,
            "allow_login_shell = true",
            "登录 shell 会加载更多用户脚本与环境，扩大命令注入面。",
            "非必要不开启；开启时确保 shell 配置未被篡改。",
        )

    servers: dict = {}
    for section in _parse_toml_sections(text):
        name = section["name"]
        if not name.startswith("mcp_servers."):
            continue
        parts = name.split(".")
        server = parts[1]
        values = _section_values(section)
        record = servers.setdefault(server, {"command": "", "args": [], "url": "", "env": {}})
        if "command" in values:
            record["command"] = values["command"]
        if "args" in values:
            record["args"] = values["args"]
        if "url" in values:
            record["url"] = values["url"]
        if len(parts) >= 3 and parts[2] == "env":
            record["env"] = values

    for server, record in servers.items():
        command_line = " ".join([record["command"], record["args"]]).strip()
        reasons = suspicious_command(command_line)
        if reasons:
            add(
                findings,
                "MCP_SUSPICIOUS_COMMAND",
                "high",
                "持久化配置",
                config,
                f"[mcp_servers.{server}] command/args 命中：{'、'.join(reasons)}；{command_line}",
                "MCP server 会被宿主反复启动，命令里的临时目录、launchctl、下载器或安装动作是典型的持久化/后利用特征。",
                "立即停用该配置；按 references/incident-response.md 保留证据后删除，并核查是否有对应恶意包。",
            )
        elif record["command"]:
            command = record["command"]
            absolute = command.startswith("/") or re.match(r"^[A-Za-z]:\\", command)
            if absolute and not command.startswith(STANDARD_BIN_PREFIXES):
                add(
                    findings,
                    "MCP_NONSTANDARD_BINARY",
                    "medium",
                    "持久化配置",
                    config,
                    f"[mcp_servers.{server}] command={command}",
                    "MCP 可执行文件不在常见安装位置，来源需要核对。",
                    "确认该文件由你安装、校验签名/哈希与来源；否则禁用。",
                )
        if record["url"] and not _host_official(_url_host(record["url"])):
            add(
                findings,
                "MCP_REMOTE_ENDPOINT",
                "medium",
                "持久化配置",
                config,
                f"[mcp_servers.{server}] url={record['url']}",
                "远程 MCP 服务器会接收你发给它的数据，并可在工具描述里携带注入内容。",
                "只连接可信来源；核对域名、证书与提供方文档。",
            )
        env_keys = list(record["env"].keys())
        if env_keys:
            add(
                findings,
                "MCP_ENV_CREDENTIALS",
                "info",
                "持久化配置",
                config,
                f"[mcp_servers.{server}.env] keys={', '.join(env_keys[:8])}",
                "MCP 配置内嵌环境变量（可能含凭据），配置文件泄露即凭据泄露。",
                "确认权限为 600，且只放该 server 必需的最小凭据。",
            )

    # 全文件兜底：配置里出现后利用特征即高危。
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if any(token in lowered for token in ("/tmp/", "/private/tmp/", "launchctl", "base64 -d", "base64 --decode", "function-color", "function-flag")):
            add(
                findings,
                "CONFIG_POSTEXEC_PATTERN",
                "high",
                "持久化配置",
                config,
                f"{line_no}行：{line}",
                "agent 的机器级配置出现临时目录/launchctl/base64 执行/IoC 包名，符合投毒后写入持久化配置的特征。",
                "按已失陷处理：停止 agent、保留证据、清理配置并轮换凭据。",
            )
            break

    for section in _parse_toml_sections(text):
        name = section["name"]
        if not name.startswith("projects."):
            continue
        values = _section_values(section)
        project_path = name[len("projects.") :].strip().strip('"').strip("'")
        trust = values.get("trust_level", "").strip('"')
        if _looks_untrusted_location(Path(project_path)) and trust != "untrusted":
            add(
                findings,
                "CODEX_PROJECT_IN_UNTRUSTED_DIR",
                "medium",
                "宿主姿态",
                config,
                f'[projects."{project_path}"] trust_level={trust or "默认"}',
                "对下载/桌面/临时目录配置了宽松信任，等于允许该目录的 AGENTS.md 与项目级配置生效。",
                '改为 trust_level = "untrusted" 或移除该条目；不要把 agent 指向这些目录。',
            )

    if stat.S_IMODE(config.stat().st_mode) & 0o077:
        add(
            findings,
            "CODEX_CONFIG_PERMISSIONS",
            "low",
            "配置卫生",
            config,
            f"权限 {oct(stat.S_IMODE(config.stat().st_mode))}",
            "配置可能含 MCP 凭据或路径信息，其他本机用户不应可读。",
            "chmod 600 ~/.codex/config.toml",
        )
    return findings


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


def scan_claude(home: Path, cwd: Path) -> list:
    findings: list = []
    settings_files = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
        Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
        Path("/etc/claude-code/managed-settings.json"),
    ]
    for settings_path in settings_files:
        if not settings_path.is_file():
            continue
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            add(
                findings,
                "CLAUDE_SETTINGS_UNREADABLE",
                "low",
                "配置卫生",
                settings_path,
                "JSON 无法解析",
                "无法审阅的配置文件不应保留在 agent 会加载的位置。",
                "人工检查该文件；确认不是被脚本半写入。",
            )
            continue
        if not isinstance(data, dict):
            continue

        if "managed-settings.json" in str(settings_path):
            add(
                findings,
                "CLAUDE_MANAGED_SETTINGS",
                "info",
                "宿主姿态",
                settings_path,
                "存在组织级 managed settings",
                "managed 配置优先级最高，可能覆盖审批与沙箱行为；排查时应一并核对。",
                "对照组织下发的基线检查，尤其是 env/hooks/permissions。",
            )

        env = data.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if not isinstance(value, str):
                    continue
                if key.upper() in {
                    "ANTHROPIC_BASE_URL",
                    "ANTHROPIC_API_URL",
                    "OPENAI_BASE_URL",
                    "OPENAI_API_BASE",
                    "CHATGPT_BASE_URL",
                }:
                    findings.extend(_check_base_url(value, f"env.{key}", settings_path))
                if re.match(r"(?i)OPENAI|ANTHROPIC", key) and ("KEY" in key.upper() or "TOKEN" in key.upper()):
                    add(
                        findings,
                        "CLAUDE_SETTINGS_EMBEDS_CREDENTIAL",
                        "info",
                        "配置卫生",
                        settings_path,
                        f"env.{key}=<redacted>",
                        "凭据写在 settings 文件里，文件被读取/提交即泄露。",
                        "改用系统 Keychain 或受管凭据；确认文件权限 600 且不入库。",
                    )
        if data.get("apiKeyHelper"):
            add(
                findings,
                "CLAUDE_API_KEY_HELPER",
                "medium",
                "配置卫生",
                settings_path,
                f"apiKeyHelper={redact(data.get('apiKeyHelper'))}",
                "宿主会执行该命令获取密钥；被篡改即可注入任意命令或截获凭据。",
                "核对命令来源与文件权限；不认识就删除。",
            )
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event, entries in hooks.items():
                text = json.dumps(entries, ensure_ascii=False)
                reasons = suspicious_command(text)
                if reasons:
                    add(
                        findings,
                        "CLAUDE_HOOK_SUSPICIOUS",
                        "high",
                        "持久化配置",
                        settings_path,
                        f"hooks.{event} 命中：{'、'.join(reasons)}；{text[:200]}",
                        "hook 会在工具调用前后自动执行，是持久化与命令执行的高价值位置。",
                        "停用该 hook，保留证据后清理；核查是谁写入的。",
                    )
                else:
                    add(
                        findings,
                        "CLAUDE_HOOK_PRESENT",
                        "medium",
                        "持久化配置",
                        settings_path,
                        f"hooks.{event}={redact(text)}",
                        "hook 会无需你逐次确认地执行命令，新增 hook 需要来源可信。",
                        "确认 hook 由你安装；不认识的删除。",
                    )
        permissions = data.get("permissions")
        if isinstance(permissions, dict):
            if permissions.get("defaultMode") in {"bypassPermissions", "acceptEdits"}:
                severity = "high" if permissions.get("defaultMode") == "bypassPermissions" else "medium"
                add(
                    findings,
                    "CLAUDE_PERMISSION_MODE",
                    severity,
                    "宿主姿态",
                    settings_path,
                    f"permissions.defaultMode={permissions.get('defaultMode')}",
                    "默认模式绕过了逐次确认，被注入后可直接改文件/执行命令。",
                    "改回默认或 plan/manual 模式；不要长期使用 bypassPermissions。",
                )
            allow = permissions.get("allow")
            if isinstance(allow, list):
                broad = [item for item in allow if isinstance(item, str) and re.search(r"(?i)^bash(\(|$|\*)", item)]
                if broad:
                    add(
                        findings,
                        "CLAUDE_BROAD_BASH_ALLOW",
                        "medium",
                        "宿主姿态",
                        settings_path,
                        f"permissions.allow 含 {broad[:5]}",
                        "宽泛的 Bash 允许规则让注入内容更容易直接执行命令。",
                        "改为按命令前缀的最小允许列表，保留审批。",
                    )
        if data.get("enableAllProjectMcpServers"):
            add(
                findings,
                "CLAUDE_ALL_PROJECT_MCP",
                "medium",
                "持久化配置",
                settings_path,
                "enableAllProjectMcpServers=true",
                "自动信任仓库里的 .mcp.json，克隆陌生仓库即可引入 MCP server。",
                "关闭自动信任，逐个审阅 .mcp.json 后再启用。",
            )

    user_mcp = home / ".claude.json"
    if user_mcp.is_file():
        try:
            data = json.loads(user_mcp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            servers = data.get("mcpServers")
            if isinstance(servers, dict):
                for name, record in servers.items():
                    if not isinstance(record, dict):
                        continue
                    command = record.get("command") or ""
                    args = record.get("args") or []
                    command_line = " ".join([str(command), " ".join(str(a) for a in args)]).strip()
                    reasons = suspicious_command(command_line)
                    if reasons:
                        add(
                            findings,
                            "MCP_SUSPICIOUS_COMMAND",
                            "high",
                            "持久化配置",
                            user_mcp,
                            f"mcpServers.{name} 命中：{'、'.join(reasons)}；{command_line}",
                            "MCP server 会被宿主反复启动；临时目录/下载器/安装动作是典型后利用特征。",
                            "停用该 server，保留证据后清理并核查包来源。",
                        )
                    elif command:
                        add(
                            findings,
                            "MCP_SERVER_PRESENT",
                            "low",
                            "持久化配置",
                            user_mcp,
                            f"mcpServers.{name} command={command}",
                            "MCP 配置是持久化与供应链入口，需知道每个 server 为什么存在。",
                            "逐个核对来源与必要性；不用的删除。",
                        )
    return findings


# ---------------------------------------------------------------------------
# Hermes / DSH / 通用
# ---------------------------------------------------------------------------


def scan_hermes(home: Path) -> list:
    findings: list = []
    config = home / ".hermes" / "config.yaml"
    if not config.is_file():
        return findings
    text = read_text_limited(config, max_bytes=2_000_000)
    if not text:
        return findings
    for match in BASE_URL_ENV_RE.finditer(text):
        findings.extend(_check_base_url(match.group(2), match.group(1), config))
    for match in BASE_URL_KEY_RE.finditer(text):
        findings.extend(_check_base_url(match.group(2), match.group(1), config))

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.match(r"^approvals:\s*$", line):
            for follow in lines[index + 1 : index + 8]:
                mode = re.match(r"^\s+mode:\s*[\"']?(\w+)", follow)
                if not mode:
                    if follow and not follow.startswith((" ", "\t")):
                        break
                    continue
                if mode.group(1).lower() in {"off", "never", "disabled"}:
                    add(
                        findings,
                        "HERMES_APPROVALS_OFF",
                        "medium",
                        "宿主姿态",
                        config,
                        f"approvals.mode={mode.group(1)}",
                        "审批关闭后，被注入的动作不需要用户确认即可执行。",
                        "改回可确认模式；在隔离环境中才允许关闭。",
                    )
                break
    if stat.S_IMODE(config.stat().st_mode) & 0o077:
        add(
            findings,
            "HERMES_CONFIG_PERMISSIONS",
            "low",
            "配置卫生",
            config,
            f"权限 {oct(stat.S_IMODE(config.stat().st_mode))}",
            "配置可能含凭据；其他本机用户不应可读。",
            "chmod 600 ~/.hermes/config.yaml",
        )
    return findings


def scan_dsh(home: Path) -> list:
    findings: list = []
    dsh = home / ".dsh"
    if not dsh.is_dir():
        return findings
    config_files = []
    for pattern in ("*.json", "*.yml", "*.yaml", "*.toml"):
        config_files.extend(dsh.glob(pattern))
    for config in config_files:
        try:
            if config.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        text = read_text_limited(config)
        if not text:
            continue
        for match in BASE_URL_ENV_RE.finditer(text):
            findings.extend(_check_base_url(match.group(2), match.group(1), config))
    agents = dsh / "AGENTS.md"
    if agents.is_symlink():
        try:
            target = Path(os.path.realpath(agents))
        except OSError:
            target = None
        if target is not None and _looks_untrusted_location(target):
            add(
                findings,
                "DSH_GLOBAL_INSTRUCTIONS_IN_UNTRUSTED_DIR",
                "high",
                "指令投毒面",
                agents,
                f"符号链接指向 {target}",
                "全局指令文件指向下载/桌面/临时目录，等于把不可信文本提升为所有会话的最高指令。",
                "把全局指令恢复到你自己维护的源文件；检查该目录来源。",
            )
        elif target is not None:
            add(
                findings,
                "DSH_GLOBAL_INSTRUCTIONS_LINK",
                "info",
                "指令投毒面",
                agents,
                f"全局 AGENTS.md 是符号链接 -> {target}",
                "全局指令来自仓库文件；仓库被改就会影响所有会话。",
                "确认链接目标属于你的受控仓库，并纳入版本审查。",
            )
    credentials = dsh / ".credentials.yaml"
    if credentials.is_file():
        mode = stat.S_IMODE(credentials.stat().st_mode)
        if mode & 0o077:
            add(
                findings,
                "DSH_CREDENTIALS_PERMISSIONS",
                "medium",
                "配置卫生",
                credentials,
                f"权限 {oct(mode)}",
                "本机其他用户可读凭据文件。",
                "chmod 600 ~/.dsh/.credentials.yaml",
            )
    return findings


# ---------------------------------------------------------------------------
# 环境变量 / shell 配置 / 持久化 / 供应链残留
# ---------------------------------------------------------------------------


def scan_environment(environ=None) -> list:
    findings: list = []
    environ = dict(os.environ if environ is None else environ)
    base_url_keys = (
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "CHATGPT_BASE_URL",
        "GEMINI_API_BASE",
    )
    for key in base_url_keys:
        value = environ.get(key, "")
        if value:
            findings.extend(_check_base_url(value, f"环境变量 {key}", Path("当前进程环境")))

    dangerous = {
        "NODE_OPTIONS": ("high", "Node 启动参数可加载任意模块（--require/--import）"),
        "DYLD_INSERT_LIBRARIES": ("high", "macOS 动态库注入"),
        "LD_PRELOAD": ("high", "Linux 动态库注入"),
        "BASH_ENV": ("medium", "非交互 bash 会 source 该文件"),
        "PYTHONSTARTUP": ("medium", "Python 交互启动会执行该文件"),
        "GIT_SSH_COMMAND": ("medium", "会替换 SSH 传输命令"),
        "NODE_TLS_REJECT_UNAUTHORIZED": ("medium", "关闭 TLS 证书校验"),
    }
    for key, (severity, why) in dangerous.items():
        value = environ.get(key)
        if not value:
            continue
        if key == "NODE_TLS_REJECT_UNAUTHORIZED" and value != "0":
            continue
        if key in {"NODE_OPTIONS", "BASH_ENV", "PYTHONSTARTUP", "GIT_SSH_COMMAND"} and not re.search(
            r"/tmp/|/private/tmp/|https?://|--require|--import|--eval", value
        ):
            continue
        add(
            findings,
            "DANGEROUS_ENV_VAR",
            severity,
            "进程环境",
            Path("当前进程环境"),
            f"{key}={redact(value)}",
            why,
            "确认是否由你主动设置；来源不明时清理 shell 配置并重开终端，再核查是否已执行过不可信内容。",
        )
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        value = environ.get(key)
        if value and not re.search(r"(?i)(127\.0\.0\.1|localhost)", value):
            add(
                findings,
                "PROXY_ENV_SET",
                "low",
                "进程环境",
                Path("当前进程环境"),
                f"{key}={redact(value)}",
                "代理会看到全部流量；若不是你配置的，凭据与会话可能被中间人记录。",
                "核对代理来源；生产环境优先用受控代理，不要用来源不明的公共代理。",
            )
            break
    return findings


def scan_shell_profiles(home: Path) -> list:
    findings: list = []
    profiles = [
        home / ".zshrc",
        home / ".zprofile",
        home / ".zshenv",
        home / ".bash_profile",
        home / ".bash_login",
        home / ".profile",
        home / ".config" / "fish" / "config.fish",
    ]
    alias_re = re.compile(
        r"(?i)^\s*alias\s+(codex|claude|cursor-agent|gemini|dsh)\s*=\s*['\"]?(.*)$"
    )
    for profile in profiles:
        if not profile.is_file():
            continue
        text = read_text_limited(profile, max_bytes=500_000)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for match in BASE_URL_ENV_RE.finditer(line):
                findings.extend(_check_base_url(match.group(2), f"{match.group(1)}（shell 配置）", profile))
            alias = alias_re.match(stripped)
            if alias and re.search(
                r"(?i)dangerously|--yolo|bypass|skip-permissions|danger-full-access|approval[s_-]*never|\s-a\s+never",
                alias.group(2),
            ):
                add(
                    findings,
                    "DANGEROUS_ALIAS",
                    "high",
                    "进程环境",
                    profile,
                    f"{line_no}行：{stripped}",
                    "alias 把所有会话默认切到无审批/无沙箱；被注入时没有任何拦截点。",
                    "删除或改成显式临时开启；不要让它成为默认。",
                )
                continue
            reasons = suspicious_command(stripped)
            if reasons and re.search(r"(/tmp/|/private/tmp/|base64|launchctl)", stripped):
                add(
                    findings,
                    "SHELL_PROFILE_SUSPICIOUS",
                    "high",
                    "持久化配置",
                    profile,
                    f"{line_no}行：{stripped}",
                    f"shell 配置命中后利用特征：{'、'.join(reasons)}",
                    "登录即执行；按已失陷处理，保留证据后清理并轮换凭据。",
                )
    return findings


def scan_persistence(home: Path, use_subprocess: bool) -> list:
    findings: list = []
    plist_dirs = [
        home / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    for plist_dir in plist_dirs:
        if not plist_dir.is_dir():
            continue
        for plist in sorted(plist_dir.glob("*.plist")):
            try:
                with open(plist, "rb") as handle:
                    data = plistlib.load(handle)
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            # 只看真正会被执行的命令，避免把 StandardErrorPath=/tmp/*.log 这类正常字段误报。
            program = data.get("Program") or ""
            args = data.get("ProgramArguments") or []
            command_line = " ".join([str(program), " ".join(str(arg) for arg in args)]).strip()
            reasons = suspicious_command(command_line)
            high_signal = re.search(
                r"(?i)(/tmp/|/private/tmp/|function-color|function-flag|base64\s+(-d|--decode)|"
                r"launchctl\s+submit|curl|wget|/dev/tcp)",
                command_line,
            )
            if reasons and high_signal:
                add(
                    findings,
                    "LAUNCH_PLIST_SUSPICIOUS",
                    "high",
                    "持久化配置",
                    plist,
                    f"命令命中：{'、'.join(reasons)}；{redact(command_line)}",
                    "登录/开机自启项引用临时目录或下载执行，符合持久化特征。",
                    "保留文件副本后卸载该 LaunchAgent，并核查写入者与相关包。",
                )
            elif reasons:
                # 如 osascript 自启：可疑但可能是正常软件，交给用户核对来源。
                add(
                    findings,
                    "LAUNCH_PLIST_SCRIPT",
                    "medium",
                    "持久化配置",
                    plist,
                    f"命令命中：{'、'.join(reasons)}；{redact(command_line)}",
                    "自启项通过脚本解释器执行命令，来源需要核对。",
                    "确认该自启项由你安装的软件创建；未知来源按事件响应处理。",
                )
    systemd_dir = home / ".config" / "systemd" / "user"
    if systemd_dir.is_dir():
        for unit in sorted(systemd_dir.glob("*.service")):
            text = read_text_limited(unit, max_bytes=500_000)
            if not text:
                continue
            exec_line = next((line for line in text.splitlines() if line.strip().startswith("ExecStart=")), "")
            reasons = suspicious_command(exec_line)
            if reasons:
                add(
                    findings,
                    "SYSTEMD_UNIT_SUSPICIOUS",
                    "high",
                    "持久化配置",
                    unit,
                    f"ExecStart 命中：{'、'.join(reasons)}",
                    "用户级 systemd 服务会在登录后自动执行。",
                    "停用并删除该 unit，核查写入者。",
                )
    if use_subprocess:
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if result is not None and result.returncode == 0:
            for line_no, line in enumerate(result.stdout.splitlines(), start=1):
                if line.strip().startswith("#") or not line.strip():
                    continue
                reasons = suspicious_command(line)
                if reasons and re.search(r"(/tmp/|/private/tmp/|curl|base64|launchctl|http)", line):
                    add(
                        findings,
                        "CRON_SUSPICIOUS",
                        "high",
                        "持久化配置",
                        Path("crontab -l"),
                        f"{line_no}行：{redact(line)}",
                        f"定时任务命中后利用特征：{'、'.join(reasons)}",
                        "确认任务来源；不认识的任务先禁用并保留证据。",
                    )
    return findings


def _suspicious_npm_globals(home: Path) -> list:
    findings: list = []
    try:
        result = subprocess.run(
            ["npm", "ls", "-g", "--depth=0", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return findings
    try:
        data = json.loads(result.stdout or "{}")
    except ValueError:
        return findings
    dependencies = data.get("dependencies") or {}
    if not isinstance(dependencies, dict):
        return findings
    for name in dependencies:
        if name in IOC_PACKAGES or name.startswith("function-"):
            add(
                findings,
                "IOC_PACKAGE_INSTALLED",
                "high",
                "供应链残留",
                Path("npm -g"),
                f"全局安装包 {name}",
                "该包名与公开投毒事件 IoC 匹配，可能已在机器上执行过安装脚本。",
                "卸载该包，清理 npm 缓存，并轮换机器上可被读取的凭据。",
            )
    return findings


def scan_supply_chain_residue(home: Path, use_subprocess: bool) -> list:
    findings: list = []
    for directory in (Path("/tmp"), Path("/private/tmp")):
        if not directory.is_dir():
            continue
        for candidate in directory.glob("*ptools*"):
            add(
                findings,
                "IOC_TMP_ARTIFACT",
                "high",
                "供应链残留",
                candidate,
                f"临时目录存在 {candidate.name}",
                "公开投毒事件使用 /tmp/ptools 作为安装目录。",
                "保留文件列表作为证据后删除；核查 npm 日志与网络连接记录。",
            )
    if use_subprocess:
        findings.extend(_suspicious_npm_globals(home))
        cache_index = home / ".npm" / "_cacache" / "index-v5"
        if cache_index.is_dir():
            try:
                result = subprocess.run(
                    ["grep", "-rl", "--", "function-color", str(cache_index)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                result = None
            if result is not None and result.stdout.strip():
                hits = [line for line in result.stdout.splitlines() if line.strip()][:5]
                add(
                    findings,
                    "IOC_NPM_CACHE",
                    "high",
                    "供应链残留",
                    cache_index,
                    f"npm 缓存索引命中 function-color：{'; '.join(redact(h) for h in hits)}",
                    "机器下载过该恶意包，即使已卸载也可能执行过安装脚本。",
                    "清理 npm 缓存；检查安装时间与当时的 shell 历史/网络访问；轮换凭据。",
                )
    npmrc = home / ".npmrc"
    if npmrc.is_file():
        text = read_text_limited(npmrc, max_bytes=200_000)
        if text:
            for line_no, line in enumerate(text.splitlines(), start=1):
                if re.match(r"(?i)^\s*registry\s*=\s*(https?://)", line) and "registry.npmjs.org" not in line:
                    add(
                        findings,
                        "NPM_REGISTRY_OVERRIDE",
                        "medium",
                        "供应链残留",
                        npmrc,
                        f"{line_no}行：{redact(line)}",
                        "非官方 registry 可以返回被替换的包与安装脚本。",
                        "确认这是你配置的私有源；否则删除并用 npm config get registry 复核。",
                    )
                if "_authToken" in line:
                    add(
                        findings,
                        "NPM_AUTH_TOKEN",
                        "info",
                        "配置卫生",
                        npmrc,
                        f"{line_no}行：{redact(line.split('=')[0])}=<redacted>",
                        "该文件含 registry 凭据，泄露可被用于投毒发布。",
                        "确认文件权限 600；不要把 .npmrc 提交进仓库。",
                    )
    for pip_config in (
        home / ".config" / "pip" / "pip.conf",
        home / "Library" / "Application Support" / "pip" / "pip.conf",
    ):
        if not pip_config.is_file():
            continue
        text = read_text_limited(pip_config, max_bytes=200_000)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if re.match(r"(?i)^\s*(extra-)?index-url\s*=", line) and "pypi.org" not in line:
                add(
                    findings,
                    "PIP_INDEX_OVERRIDE",
                    "medium",
                    "供应链残留",
                    pip_config,
                    f"{line_no}行：{redact(line)}",
                    "非官方 Python 包源可以返回被替换的包与构建脚本。",
                    "确认是你配置的私有源；否则删除并复核 pip config list。",
                )
    return findings


def scan_secret_permissions(home: Path) -> list:
    findings: list = []
    checks = [
        (home / ".ssh", 0o700, "SSH 目录"),
        (home / ".aws" / "credentials", 0o600, "AWS 凭据"),
        (home / ".config" / "gh" / "hosts.yml", 0o600, "GitHub CLI 凭据"),
    ]
    for path, expected, label in checks:
        if not path.exists():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            add(
                findings,
                "SECRET_FILE_PERMISSIONS",
                "low",
                "配置卫生",
                path,
                f"{label}权限 {oct(mode)}（建议 {oct(expected)}）",
                "权限过宽会让同机其他用户/进程读取凭据。",
                f"chmod {expected:o} {path}",
            )
    return findings


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def scan_all(home: Path, cwd: Path, use_subprocess: bool = True) -> list:
    findings: list = []
    findings.extend(scan_instruction_files(home, cwd))
    findings.extend(scan_codex(home))
    findings.extend(scan_claude(home, cwd))
    findings.extend(scan_hermes(home))
    findings.extend(scan_dsh(home))
    findings.extend(scan_environment())
    findings.extend(scan_shell_profiles(home))
    findings.extend(scan_persistence(home, use_subprocess))
    findings.extend(scan_supply_chain_residue(home, use_subprocess))
    findings.extend(scan_secret_permissions(home))
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="多宿主 Agent 信息安全只读自检（不联网、不执行被扫描内容、不写文件）"
    )
    parser.add_argument("--home", default=str(Path.home()), help="用户主目录（测试时可覆盖）")
    parser.add_argument("--cwd", default=os.getcwd(), help="当前工作目录")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="none",
        help="达到该级别时退出码为 1（默认 none）",
    )
    parser.add_argument(
        "--no-subprocess",
        action="store_true",
        help="跳过 npm/crontab 等只读子进程检查",
    )
    args = parser.parse_args(argv)
    findings = scan_all(
        Path(args.home).expanduser(),
        Path(args.cwd).expanduser(),
        use_subprocess=not args.no_subprocess,
    )
    emit(findings, args.format, "Agent 信息安全自检（只读）")
    if args.fail_on == "none":
        return 0
    return fail_on_exit_code(findings, {"low": "low", "medium": "medium", "high": "high"}[args.fail_on])


if __name__ == "__main__":
    raise SystemExit(main())
