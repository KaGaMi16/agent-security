#!/usr/bin/env python3
"""下载/克隆项目的只读投毒预检。

只读取文件、不执行任何内容、不联网、不写文件；符号链接不会被跟随。
它给出的是"需要人工复核的信号"，不是安全证明。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    OFFICIAL_MODEL_HOSTS,
    add,
    emit,
    fail_on_exit_code,
    is_probably_binary,
    read_text_limited,
    redact,
    scan_injection,
    suspicious_command,
    unicode_anomalies,
)

SKIP_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    "dist",
    "build",
    "target",
    "coverage",
}

INSTRUCTION_REL = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    "COPILOT.md",
    ".github/copilot-instructions.md",
}
CONFIG_REL = {".mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".codex/config.toml"}
SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".command"}
LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly")
DANGEROUS_INSTALL_RE = re.compile(
    r"(?i)(curl|wget|base64|/tmp/|/private/tmp/|nc\s|ncat\s|node\s+-e|python[0-9.]*\s+-c|"
    r"os\.system|subprocess|child_process|eval\s*\(|Function\s*\()"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----")
BASE_URL_RE = re.compile(
    r"(?i)\b(ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|OPENAI_BASE_URL|OPENAI_API_BASE|"
    r"CHATGPT_BASE_URL|base_url|baseURL)\b\s*[:=]\s*[\"']?(https?://[^\s\"',]+)"
)
BINARY_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"MZ")


def _rel(root: Path, path: Path) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


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
        "仓库配置把模型网关改到非官方地址；宿主可能把凭据发给第三方，或收到伪造的工具调用。",
        "不要在主机上使用该配置；核对仓库历史与作者意图。",
    )
    return findings


def _iter_files(root: Path, max_files: int):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        rel_dir = _rel(root, current)
        if rel_dir != "." and rel_dir.count("/") >= 8:
            dirnames[:] = []
        dirnames[:] = sorted(
            name for name in dirnames if name not in SKIP_DIRS
        )
        if current.name == ".git":
            dirnames[:] = []
            for hook in sorted((current / "hooks").glob("*")) if (current / "hooks").is_dir() else []:
                if hook.is_file() and not hook.name.endswith(".sample"):
                    yield hook
            continue
        for filename in sorted(filenames):
            if count >= max_files:
                return
            count += 1
            yield current / filename


def _scan_instruction_text(path: Path, text: str) -> list:
    findings: list = []
    anomalies = unicode_anomalies(text)
    if anomalies:
        sample = "、".join(f"{item['codepoint']}@{item['line']}行" for item in anomalies[:5])
        add(
            findings,
            "HIDDEN_UNICODE",
            "high",
            "指令投毒面",
            path,
            f"发现 {len(anomalies)} 个零宽/双向控制字符：{sample}",
            "零宽/双向控制字符可用于隐藏 prompt；正常规则文件不需要它们。",
            "以原始字节审查并核对 git 历史；无法解释时不要在该目录启动 agent。",
        )
    for hit in scan_injection(text):
        add(
            findings,
            f"INJECTION/{hit['rule']}",
            "high" if hit["severity"] == "high" else "medium",
            "指令投毒面",
            path,
            f"{hit['line']}行：{hit['snippet']}",
            hit["label"],
            "核对来源与 diff；陌生仓库出现这类语句时不要按内容执行。",
        )
    return findings


def _scan_instruction_file(path: Path) -> list:
    findings: list = []
    add(
        findings,
        "AGENT_INSTRUCTION_FILE",
        "medium",
        "指令投毒面",
        path,
        "仓库内包含会被 agent 自动加载的指令/配置文件",
        "agent 会把该文件当指令读入；陌生仓库等于让作者影响你的会话。",
        "启动 agent 前逐行审阅；确认它只描述项目本身，不含要求执行的动作。",
    )
    text = read_text_limited(path)
    if not text:
        return findings
    findings.extend(_scan_instruction_text(path, text))
    return findings


def _scan_package_json(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path)
    if not text:
        return findings
    try:
        data = json.loads(text)
    except ValueError:
        add(
            findings,
            "PACKAGE_JSON_INVALID",
            "low",
            "供应链",
            path,
            "package.json 解析失败",
            "损坏或手工拼接的清单可能隐藏安装脚本。",
            "人工检查该文件与 lockfile。",
        )
        return findings
    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for name in LIFECYCLE_SCRIPTS:
            command = scripts.get(name)
            if not command:
                continue
            reasons = suspicious_command(command)
            dangerous = bool(DANGEROUS_INSTALL_RE.search(command))
            severity = "high" if dangerous or reasons else "medium"
            add(
                findings,
                "NPM_LIFECYCLE_SCRIPT",
                severity,
                "供应链",
                path,
                f"scripts.{name}={redact(command)}" + (f" 命中：{'、'.join(reasons)}" if reasons else ""),
                "npm install 会自动运行生命周期脚本；这是最常见的依赖投毒执行入口。",
                "不要直接 npm install；先只读审阅脚本，必要时 --ignore-scripts 安装后再逐项核对。",
            )
    dependencies = data.get("dependencies") or {}
    dev_dependencies = data.get("devDependencies") or {}
    for scope, table in (("dependencies", dependencies), ("devDependencies", dev_dependencies)):
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if not isinstance(spec, str):
                continue
            if re.match(r"(?i)^https?://", spec):
                add(
                    findings,
                    "NPM_INSECURE_DEPENDENCY",
                    "medium",
                    "供应链",
                    path,
                    f"{scope}.{name}={spec}",
                    "直接 http 依赖可被中间人替换，也没法用 registry 完整性校验。",
                    "改为 registry 版本并锁定；核对哈希。",
                )
            elif re.match(r"(?i)^git\+http://", spec):
                add(
                    findings,
                    "NPM_INSECURE_GIT_DEPENDENCY",
                    "medium",
                    "供应链",
                    path,
                    f"{scope}.{name}={spec}",
                    "明文 git 传输可被篡改。",
                    "改用 https 或固定 commit + 哈希校验。",
                )
    return findings


def _scan_requirements(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path, max_bytes=500_000)
    if not text:
        return findings
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"(?i)^--?extra-index-url", stripped) or re.search(
            r"(?i)^--?trusted-host", stripped
        ):
            add(
                findings,
                "PIP_EXTRA_INDEX",
                "medium",
                "供应链",
                path,
                f"{line_no}行：{redact(stripped)}",
                "额外包源可提供被替换的同名包；--trusted-host 会跳过证书校验。",
                "核对包源域名；不要沿用仓库里的 extra-index/trusted-host。",
            )
        elif re.search(r"(?i)^git\+http://", stripped) or re.search(r"(?i)^https?://[^\s]+\.(whl|tar\.gz)", stripped):
            add(
                findings,
                "PIP_DIRECT_URL",
                "low",
                "供应链",
                path,
                f"{line_no}行：{redact(stripped)}",
                "直接 URL 安装绕过包索引的元数据审查。",
                "固定版本与哈希；条件允许改用锁定文件。",
            )
    return findings


def _scan_setup_py(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path, max_bytes=500_000)
    if not text:
        return findings
    reasons = suspicious_command(text)
    if reasons and re.search(r"(?i)(subprocess|os\.system|exec\(|eval\(|cmdclass)", text):
        add(
            findings,
            "SETUP_PY_EXEC",
            "high",
            "供应链",
            path,
            f"安装脚本含命令执行特征：{'、'.join(reasons)}",
            "pip install 会执行 setup.py；混淆的命令执行等于安装即执行。",
            "不要直接 pip install；先只读审查 setup.py 与构建后端。",
        )
    elif re.search(r"cmdclass\s*=", text):
        add(
            findings,
            "SETUP_PY_CUSTOM_BUILD",
            "medium",
            "供应链",
            path,
            "setup.py 使用自定义 build 命令",
            "自定义 cmdclass 可在安装阶段执行任意代码，需要人工审查。",
            "核对自定义命令内容；陌生来源先隔离环境安装。",
        )
    return findings


def _scan_shell_script(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path, max_bytes=500_000)
    if not text:
        return findings
    hits = scan_injection(text)
    for hit in hits:
        add(
            findings,
            f"INJECTION/{hit['rule']}",
            "high" if hit["severity"] == "high" else "medium",
            "脚本执行面",
            path,
            f"{hit['line']}行：{hit['snippet']}",
            hit["label"],
            "不要执行仓库内脚本；只读审查后再决定。",
        )
    if not hits:
        for line_no, line in enumerate(text.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"(?i)(curl|wget)[^\n]{0,120}\|\s*(sudo\s+)?(ba|z|k)?sh", line):
                add(
                    findings,
                    "DOWNLOAD_AND_EXEC",
                    "high",
                    "脚本执行面",
                    path,
                    f"{line_no}行：{redact(line.strip())}",
                    "下载即执行，脚本内容可在审查之外变化。",
                    "不要执行；下载后固定哈希并人工审查。",
                )
                break
    return findings


def _scan_mcp_json(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path)
    if not text:
        return findings
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        add(
            findings,
            "MCP_FILE_PRESENT",
            "medium",
            "持久化配置",
            path,
            ".mcp.json 无法解析或结构未知",
            "项目级 MCP 配置会被宿主加载（取决于宿主信任设置）。",
            "人工审阅；不要在陌生仓库自动信任项目 MCP。",
        )
        return findings
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, record in servers.items():
            if not isinstance(record, dict):
                continue
            command = record.get("command") or record.get("url") or ""
            args = record.get("args") or []
            command_line = " ".join([str(command), " ".join(str(a) for a in args)]).strip()
            reasons = suspicious_command(command_line)
            if reasons:
                add(
                    findings,
                    "MCP_SUSPICIOUS_COMMAND",
                    "high",
                    "持久化配置",
                    path,
                    f"mcpServers.{name} 命中：{'、'.join(reasons)}；{command_line}",
                    "该 MCP server 会在宿主中反复启动，命令特征符合持久化/后利用。",
                    "不要启用；按事件响应保留证据并核查来源。",
                )
            else:
                add(
                    findings,
                    "MCP_SERVER_PRESENT",
                    "medium",
                    "持久化配置",
                    path,
                    f"mcpServers.{name}={command_line or '<remote>'}",
                    "项目级 MCP server 是供应链执行面；启用前需要来源与最小权限审查。",
                    "核对 server 来源、权限与网络访问；不确定就不要启用。",
                )
    return findings


def _scan_claude_settings(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path)
    if not text:
        return findings
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        add(
            findings,
            "CLAUDE_SETTINGS_PRESENT",
            "medium",
            "持久化配置",
            path,
            "项目级 Claude 配置无法解析",
            "项目级配置可改环境变量、hooks 与权限，需人工审阅。",
            "核对内容；不要在陌生仓库直接信任。",
        )
        return findings
    env = data.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if isinstance(value, str) and key.upper() in {
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_API_URL",
                "OPENAI_BASE_URL",
                "OPENAI_API_BASE",
            }:
                findings.extend(_check_base_url(value, f"env.{key}", path))
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            text_entries = json.dumps(entries, ensure_ascii=False)
            reasons = suspicious_command(text_entries)
            add(
                findings,
                "CLAUDE_HOOK_SUSPICIOUS" if reasons else "CLAUDE_HOOK_PRESENT",
                "high" if reasons else "medium",
                "持久化配置",
                path,
                f"hooks.{event}={redact(text_entries)}",
                "hook 会在工具调用前后自动执行命令。",
                "陌生仓库的 hooks 一律不要启用；核对来源后再考虑。",
            )
    permissions = data.get("permissions")
    if isinstance(permissions, dict) and permissions.get("defaultMode") in {
        "bypassPermissions",
        "acceptEdits",
    }:
        add(
            findings,
            "CLAUDE_PERMISSION_MODE",
            "high",
            "持久化配置",
            path,
            f"permissions.defaultMode={permissions.get('defaultMode')}",
            "项目配置要求放宽权限确认。",
            "不要接受；按宿主提示拒绝项目级放宽。",
        )
    if not findings:
        add(
            findings,
            "CLAUDE_SETTINGS_PRESENT",
            "medium",
            "持久化配置",
            path,
            "存在项目级 Claude 配置文件",
            "项目级配置会影响 host 行为，属于需要审阅的供应链面。",
            "逐项核对 env/hooks/permissions；确认无异常再启用。",
        )
    return findings


def _scan_codex_config(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path, max_bytes=2_000_000)
    if not text:
        return findings
    reasons = suspicious_command(text)
    if reasons:
        add(
            findings,
            "CODEX_PROJECT_CONFIG_SUSPICIOUS",
            "high",
            "持久化配置",
            path,
            f"项目级 Codex 配置命中：{'、'.join(reasons)}",
            "项目级配置可能写入 MCP/审批/沙箱行为，属于持久化入口。",
            "不要在该目录启动 Codex；人工审查配置来源。",
        )
    else:
        add(
            findings,
            "CODEX_PROJECT_CONFIG_PRESENT",
            "medium",
            "持久化配置",
            path,
            "存在项目级 Codex 配置",
            "项目级配置会改变宿主行为，需确认来源可信。",
            "核对配置内容与 git 历史；确认无 mcp_servers/审批放宽。",
        )
    return findings


def _scan_workflow(path: Path) -> list:
    findings: list = []
    text = read_text_limited(path, max_bytes=500_000)
    if not text:
        return findings
    if re.search(r"(?m)^\s*pull_request_target\s*:", text):
        add(
            findings,
            "CI_PULL_REQUEST_TARGET",
            "medium",
            "供应链",
            path,
            "workflow 使用 pull_request_target",
            "该触发器在持有写权限的上下文运行，若检出并执行 PR 代码可导致凭据泄漏/仓库被改。",
            "人工审查 checkout 的 ref 与 secrets 使用；不要在陌生仓库上启用自动运行。",
        )
    if re.search(r"(?m)^\s*permissions\s*:\s*write-all\s*$", text):
        add(
            findings,
            "CI_WRITE_ALL",
            "low",
            "供应链",
            path,
            "workflow 请求 write-all 权限",
            "过宽令牌会让 CI 被利用时影响更大。",
            "改为按需最小权限。",
        )
    return findings


def _scan_text_file(path: Path, rel: str) -> list:
    findings: list = []
    text = read_text_limited(path)
    if text is None:
        return findings
    if PRIVATE_KEY_RE.search(text):
        add(
            findings,
            "PRIVATE_KEY_IN_TREE",
            "high",
            "凭据泄漏",
            path,
            "文件包含私钥块",
            "私钥进入仓库/下载目录即视为泄露；下载的仓库也可能被用来收集你的密钥。",
            "不要使用该文件；确认是否为你自己的密钥，若是立即轮换。",
        )
    if os.path.basename(rel) == ".npmrc" and "_authToken" in text:
        add(
            findings,
            "NPM_TOKEN_IN_TREE",
            "high",
            "凭据泄漏",
            path,
            "_authToken=<redacted>",
            "仓库内 npm 凭据可被用于投毒发布。",
            "视为已泄露并轮换；从仓库移除。",
        )
    if re.search(r"(?i)^\s*[A-Z0-9_]+(KEY|TOKEN|SECRET|PASSWORD)\s*=\s*\S+", text, re.MULTILINE) and (
        rel.endswith(".env") or rel.endswith(".env.local")
    ):
        add(
            findings,
            "ENV_FILE_PRESENT",
            "medium",
            "凭据泄漏",
            path,
            "仓库包含 .env 且存在疑似凭据赋值",
            ".env 可能含真实凭据；也常被恶意仓库用来诱导 agent 读取。",
            "确认是否示例值；真实凭据立即轮换并从仓库移除。",
        )
    return findings


def _scan_binary(path: Path) -> list:
    findings: list = []
    try:
        with open(path, "rb") as handle:
            magic = handle.read(4)
        size = path.stat().st_size
    except OSError:
        return findings
    if any(magic.startswith(prefix) for prefix in BINARY_MAGIC) or path.suffix.lower() in {
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".node",
    }:
        add(
            findings,
            "PREBUILT_BINARY",
            "medium",
            "供应链",
            path,
            f"预编译二进制（{size} bytes，magic={magic!r}）",
            "二进制无法静态审阅，可能打包任意代码；下载的仓库带二进制时应只读隔离检查。",
            "核对来源与哈希；只在隔离环境/只读挂载中使用。",
        )
    return findings


def scan_tree(root: Path, max_files: int = 20000) -> list:
    findings: list = []
    checked = 0
    for path in _iter_files(root, max_files):
        checked += 1
        rel = _rel(root, path)
        basename = path.name
        try:
            stat_result = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(stat_result.st_mode):
            try:
                target = Path(os.path.realpath(path))
                target.relative_to(root.resolve())
            except (OSError, ValueError):
                add(
                    findings,
                    "SYMLINK_ESCAPES_TREE",
                    "medium",
                    "供应链",
                    path,
                    f"符号链接指向仓库外：{os.path.realpath(path)}",
                    "链接可让后续工具读取仓库外文件；扫描与执行都不应跟随。",
                    "人工确认链接用途；不要对陌生仓库执行会跟随链接的命令。",
                )
            continue
        if not stat.S_ISREG(stat_result.st_mode):
            continue

        if basename in INSTRUCTION_REL or rel in INSTRUCTION_REL or rel in CONFIG_REL:
            if rel in CONFIG_REL:
                if basename == ".mcp.json":
                    findings.extend(_scan_mcp_json(path))
                elif rel.startswith(".claude/"):
                    findings.extend(_scan_claude_settings(path))
                elif rel.startswith(".codex/"):
                    findings.extend(_scan_codex_config(path))
            else:
                findings.extend(_scan_instruction_file(path))
            continue

        if basename == "package.json" and rel.count("/") <= 1:
            findings.extend(_scan_package_json(path))
            continue
        if basename in {"requirements.txt", "requirements-dev.txt", "requirements.in"} or (
            basename.startswith("requirements") and basename.endswith(".txt")
        ):
            findings.extend(_scan_requirements(path))
            continue
        if basename == "setup.py":
            findings.extend(_scan_setup_py(path))
            continue
        if path.suffix.lower() in SCRIPT_SUFFIXES:
            findings.extend(_scan_shell_script(path))
            continue
        if rel.startswith(".github/workflows/") and path.suffix.lower() in {".yml", ".yaml"}:
            findings.extend(_scan_workflow(path))
            continue
        if rel.startswith(".git/hooks/"):
            findings.extend(_scan_binary(path))
            text = read_text_limited(path, max_bytes=500_000)
            if text:
                reasons = suspicious_command(text)
                severity = "high" if reasons else "medium"
                add(
                    findings,
                    "GIT_HOOK_ACTIVE",
                    severity,
                    "供应链",
                    path,
                    f"存在可执行 git hook：{path.name}" + (f" 命中：{'、'.join(reasons)}" if reasons else ""),
                    "git hook 会在 clone/fetch/commit 等操作时执行；正常克隆不会自动启用，但配置 hooksPath 或复制仓库时会。",
                    "检查 git config core.hooksPath；陌生仓库的 hook 文件不要执行。",
                )
            continue
        if path.suffix.lower() in {".js", ".mjs", ".cjs"}:
            text = read_text_limited(path, max_bytes=1_000_000)
            if text:
                findings.extend(_scan_obfuscated_js(path, text))
            continue
        if basename.startswith("README") and basename.lower().endswith(".md") and rel.count("/") == 0:
            text = read_text_limited(path)
            if text:
                findings.extend(_scan_instruction_text(path, text))
            continue

        findings.extend(_scan_text_file(path, rel))
        findings.extend(_scan_binary(path))
    if checked >= max_files:
        add(
            findings,
            "SCAN_LIMIT_REACHED",
            "info",
            "扫描范围",
            root,
            f"达到文件上限 {max_files}，结果可能不完整",
            "大仓库中后面未扫描的文件仍可能有问题。",
            "缩小到具体可疑目录或提高上限后重扫。",
        )
    return findings


def _scan_obfuscated_js(path: Path, text: str) -> list:
    findings: list = []
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return findings
    longest = max(len(line) for line in lines)
    if longest > 3000 and re.search(r"(?i)(eval\s*\(|new Function\s*\(|atob\s*\()", text):
        add(
            findings,
            "OBFUSCATED_JS",
            "medium",
            "供应链",
            path,
            f"单行长度 {longest} 且含 eval/Function/atob",
            "压缩/混淆代码可能在安装或导入时执行隐藏逻辑。",
            "不要运行；在隔离环境用可读版本或沙箱动态分析。",
        )
    return findings


def verdict(findings: list) -> dict:
    highest = max((item.severity for item in findings), key=lambda s: {"high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0), default="info")
    if highest == "high":
        return {
            "level": "HIGH-RISK",
            "message": "发现高危信号：不要在该目录启动有执行/网络权限的 agent，也不要运行安装脚本；先在隔离环境只读审查。",
        }
    if highest == "medium":
        return {
            "level": "REVIEW-REQUIRED",
            "message": "存在需要人工核对的文件或配置；核对来源与 diff 后再决定是否运行。",
        }
    return {
        "level": "NO-OBVIOUS-SIGNAL",
        "message": "未发现明显投毒特征；这不等于安全，运行前仍需最小权限与隔离。",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="下载/克隆项目的只读投毒预检（不执行、不联网、不写文件）"
    )
    parser.add_argument("root", help="要预检的目录，例如 ~/Downloads/repo 或刚 clone 的仓库")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="none",
        help="达到该级别时退出码为 1（默认 none）",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).expanduser()
    if not root.exists() or not root.is_dir():
        print(f"目录不存在或不是目录：{root}", file=sys.stderr)
        return 2
    findings = scan_tree(root, max_files=args.max_files)
    result = verdict(findings)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "title": f"投毒预检：{root}",
                    "verdict": result,
                    "summary": {
                        "total": len(findings),
                        "high": sum(1 for f in findings if f.severity == "high"),
                        "medium": sum(1 for f in findings if f.severity == "medium"),
                        "low": sum(1 for f in findings if f.severity == "low"),
                        "info": sum(1 for f in findings if f.severity == "info"),
                    },
                    "findings": [f.to_dict() for f in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        emit(findings, "text", f"投毒预检：{root}")
        print(f"结论：{result['level']} —— {result['message']}")
    if args.fail_on == "none":
        return 0
    return fail_on_exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
