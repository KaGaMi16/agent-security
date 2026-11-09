# Agent Security

**多宿主通用的 AI coding agent 信息安全自检技能。**

[English](README.md) · MIT License · Python 3.10+

[![tests](https://github.com/KaGaMi16/agent-security/actions/workflows/tests.yml/badge.svg)](https://github.com/KaGaMi16/agent-security/actions/workflows/tests.yml)

> ## ⚠️ 不要盲目偏信这个技能
>
> 这是一个人维护的早期技能，只经过单元测试、一个合成恶意仓库夹具和**一台**真实 macOS 机器的验证，没有更大范围的检验。它**没有测过误报率/漏报率**，也没有经过对抗性测试或第三方复核。
>
> * 它**可能漏掉真实攻击**，包括新的或本地变形的攻击。
> * 它**可能误报正常项目**（CI 配置、测试夹具、你自己配置的非官方模型网关）。
> * **“没有告警”不等于安全**，只代表这几条启发式规则没发现特征。
> * 不要把它当作唯一防线，不要自动执行它给出的清理建议，也不要因此关闭 agent 的审批与沙箱。
>
> 把它当作第二双眼睛和一份可重复的检查清单，而不是权威结论。

## 这个技能防什么

Agent 会把读到的内容当指令执行。`AGENTS.md`、`CLAUDE.md`、`.mcp.json`、项目级 `.claude/settings.json`、shell 启动文件、MCP server 定义——这些会被自动加载的文件属于可执行面，而不只是文档。

公开披露的攻击链是：网页无需点击即可把纯文本 `AGENTS.md` 投放到 `~/Downloads`；用户在该目录启动 Codex 或 Claude Code；agent 把文件当成最高优先级指令，向 `~/.codex/config.toml` 写入机器级 MCP server、从临时目录安装 npm 包，或改写 `ANTHROPIC_BASE_URL` 把凭据引向攻击者网关。整个过程不需要漏洞利用二进制。Markdown 就是机器码。

本技能把防守侧拆成可重复的路径：

| 路径 | 何时用 | 产出 |
| --- | --- | --- |
| **A — 项目预检** | 刚下载/克隆了一个项目，想知道能不能跑 | 只读扫描指令文件、生命周期脚本、agent 配置、钩子、二进制、符号链接逃逸、供应链特征 |
| **B — 主机自检** | 新机器、新宿主、新插件，或怀疑 agent 配置被动过 | 只读审计 agent 配置、MCP、审批/沙箱、`base_url` 劫持、shell 启动项、持久化与 IoC 残留 |
| **C — 处置核对** | 已经看到可疑文件/命令，或怀疑已被触发 | 止损 → 留证 → 清点 → 清除 → 轮换 → 复扫 的顺序流程 |
| **D — 固定版本技能包** | 以固定版本安装第三方技能 | 核对来源 ref、逐目录指纹、receipt/spec 绑定、宿主软链 |

背景与来源见 [`references/threat-model.md`](references/threat-model.md)，包括 [Forever Security 的下载目录投毒分析](https://forever.security/blog/hijacking-ai-agents-via-downloads-folder/)、[OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)、[五眼联盟 agentic AI 指导](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services) 与 [MCP 安全最佳实践](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)。

## 安装

克隆到技能目录，再按宿主建立软链。目录名必须保持 `kgm-agent-security`，与 `SKILL.md` 里的 `name` 一致。

```bash
git clone https://github.com/KaGaMi16/agent-security.git ~/.agents/skills/kgm-agent-security

# 可选：接入各宿主
ln -s ~/.agents/skills/kgm-agent-security ~/.codex/skills/kgm-agent-security      # Codex
ln -s ~/.agents/skills/kgm-agent-security ~/.claude/skills/kgm-agent-security     # Claude Code
ln -s ~/.agents/skills/kgm-agent-security ~/.hermes/skills/kgm-agent-security     # Hermes
```

| 宿主 | 技能目录 |
| --- | --- |
| Codex | `~/.codex/skills/` |
| Claude Code | `~/.claude/skills/` |
| Hermes | `~/.hermes/skills/` |
| DeepSeek Harness、Kimi 及其他支持技能的 agent | `~/.agents/skills/` 或宿主配置的技能路径 |

无安装器、无第三方依赖、无常驻进程。Python 3.10+ 标准库即可。

## 用法

### 通过 agent

直接用自然语言提问，agent 会加载技能并走对应路径：

```text
这个仓库能跑吗？我刚 clone 到 ~/work/some-project。
```

```text
帮我查一下本机 agent 配置有没有被改过。
```

```text
我在 ~/Downloads 看到一个 AGENTS.md，好像已经在那里启动过 agent 了。
```

### 直接用命令行

```bash
SKILL=~/.agents/skills/kgm-agent-security

# A. 预检下载/克隆的项目（只读）
python3 "$SKILL/scripts/scan_untrusted_tree.py" ~/Downloads/some-project --format text

# 高危时退出码为 1（用于 CI/批处理，不要用它自动清理）
python3 "$SKILL/scripts/scan_untrusted_tree.py" ~/work/some-project --fail-on high

# B. 主机自检（只读）
python3 "$SKILL/scripts/agent_security_scan.py" --format text

# JSON 输出，便于接入工具
python3 "$SKILL/scripts/agent_security_scan.py" --format json

# D. 固定版本技能包核对（可选；布局可用参数覆盖）
python3 "$SKILL/scripts/verify_external_skills.py" --format text
```

## 检查范围

`scan_untrusted_tree.py`（仓库预检）：指令文件与隐藏 Unicode、仓库内 agent 配置、npm 生命周期脚本、非官方 registry、pip 额外索引、`setup.py` 执行、网络管道到 shell、CI 触发器、`.git/hooks`、预编译二进制、符号链接逃逸、私钥/`.npmrc` token/`.env`、混淆 JS、README 注入。

`agent_security_scan.py`（主机自检）：Codex、Claude Code、Hermes、DSH 的配置与 MCP；`*_BASE_URL` 与危险环境变量（`NODE_OPTIONS`、`DYLD_INSERT_LIBRARIES`、`BASH_ENV` 等）；shell 启动文件；LaunchAgents/LaunchDaemons、systemd user unit、crontab；`/tmp` 安装残留、npm 全局/缓存 IoC 包、`.npmrc`/`pip.conf`；凭据文件权限。

`verify_external_skills.py`：materialized 技能的逐目录指纹、spec/ref 绑定、roster、receipt 绑定、宿主断链。该脚本面向 monorepo 式固定版本技能包，默认布局沿用作者工作区（`control/base/external-skills.json`、`control/machine-local/external-skills/…`），可用 `--workspace`、`--spec`、`--receipt`、`--overlay` 指向自己的布局。

## 安全模型

* **只读**：不修改文件、不执行被扫描内容、不跟随目录软链。
* **不联网**：主机自检最多运行两条只读子进程检查（`npm ls -g`、`crontab -l`），可用 `--no-subprocess` 关闭。
* **无遥测、无更新检查。**
* **不自动清理**：删除文件、修改 agent 配置、轮换凭据都必须由用户逐项确认；先备份再操作。
* **证据留在本地**：打印前会脱敏疑似凭据。
* **`--fail-on` 只影响退出码**，不会触发清理。

本技能不会自主执行清理、配置修改或凭据轮换。

## 验证状态（依赖它之前请先读）

已经做过的：

* **21 个单元测试**（`python3 -m unittest discover -s tests`），覆盖扫描规则、软链处理、指纹篡改、过期 receipt、roster 不一致、宿主断链。
* **合成恶意仓库夹具**：11 个文件，包含带零宽字符和“不要告诉用户”的 `AGENTS.md`、`postinstall` 把远程下载管道到 `sh`、指向 `/tmp/ptools/node` 的 `.mcp.json`、非官方 `ANTHROPIC_BASE_URL` 的 `.claude/settings.json`。预检返回 `HIGH-RISK`，`--fail-on high` 退出码为 1。
* **一台真实 macOS 主机**：完整自检结果为 **0 高危**、**2 中危**（Hermes `approvals.mode: off`；一个通过 `osascript` 启动 Hermes 网关的 LaunchAgent）、**2 提示**。中危项属于配置选择，不是失陷证据。
* **一次小规模对照**：两个子代理实验中，未加载技能、能力较强的模型也能识别夹具里明显的问题。这个技能的价值是可重复的流程和确定性扫描器，**不是**“能发现强模型发现不了的问题”。

没有做过的：

* 还没有 CI 流水线，21 个测试目前手动运行。
* 没有大规模或对抗性评测，没有误报率/漏报率数据。
* 没有其他用户复核；没有在 Linux/Windows 上验证（Linux 路径只按规则实现）。
* 没有针对新型规避、二进制后门、签名但恶意的包或社工诱导的测试。

必须诚实接受的结论：**这个技能两个方向都可能错。** 每条发现都要人工核实，也永远不要把“干净报告”当作仓库、主机或技能包安全的证明。

## 不适用范围

* 审计第三方 skill 或脚本**本身是否恶意**（例如可用腾讯云 `skills-security-check`）；本技能只核对固定版本完整性，不判断意图。
* 泛化代码漏洞审计、渗透测试、恶意软件分析、完整数字取证。
* 替代 EDR/杀软、沙箱、最小权限或人工复核。

## 要求

* Python **3.10+**，只用标准库，无需 `pip install`。开发与实测环境为 Python 3.13，3.10–3.12 尚未实测。
* 以 macOS 路径为主要目标；包含 Linux 持久化检查但未验证；不支持 Windows。
* 对被扫描路径有读权限即可，不需要提权。

## 目录结构

```text
.
├── SKILL.md                     # 技能本体：路径选择、流程、授权规则
├── references/
│   ├── quick-check.md           # 3 分钟清单与 IoC 速查
│   ├── threat-model.md          # 攻击链、公开案例、OWASP/CISA 对照
│   ├── host-hardening.md        # 分宿主加固矩阵
│   └── incident-response.md     # 止损、留证、轮换与验证
├── scripts/
│   ├── scan_untrusted_tree.py   # 仓库预检（只读）
│   ├── agent_security_scan.py   # 主机自检（只读）
│   ├── verify_external_skills.py# 固定版本技能包核对（只读）
│   └── common.py                # 共享的发现/规则/脱敏工具
└── tests/                       # 21 个单元测试，不联网、不读真实主机
```

## 参与

欢迎提交 issue 和 PR，尤其是脱敏后的误报/漏报样例、不同宿主配置布局。请不要在 issue 里贴真实 token、私钥或未脱敏的主机日志。若发现绕过扫描器的方法，请用最小、非破坏性的复现提交 issue。

## 许可证

MIT — 见 [LICENSE](LICENSE)。
