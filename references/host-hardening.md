# 多宿主加固清单

原则先行：**不隐式信任内容、默认拒绝网络、最小权限、保留审批、记录动作、假定会出错**。下面按宿主给出可核对的落点和验证方式；具体键名以你本机安装版本的官方文档为准，不要凭旧版记忆改配置。

## 通用八条

1. 不在 `~/Downloads`、`~/Desktop` 或临时目录启动 agent；项目目录与下载目录分离。
2. 陌生仓库先跑 `scan_untrusted_tree.py`，有高危不出网、不安装、不启动。
3. 保留审批与沙箱；任何要求 `--yolo`、`bypassPermissions`、`danger-full-access`、`approvals off` 的说法先视为可疑。
4. 网络默认关闭；需要时按域名白名单放行，不给任意出网。
5. 凭据最小化：不把长期 token 放进项目/环境变量；优先短期凭据、系统钥匙串、0600 文件。
6. agent 间不隐式互信；子 agent/远程 MCP 需要可验证身份与最小 scope。
7. 高影响/不可逆动作（删数据、改系统配置、轮换、对外发送）human-in-the-loop。
8. 保留可审计记录（工具调用、配置变更），至少能在事后还原时间线。

## 宿主落点矩阵

| 宿主 | 主要配置落点 | 重点检查 | 验证方式 |
| --- | --- | --- | --- |
| Codex | `~/.codex/config.toml`、`~/.codex/*.config.toml`、项目 `.codex/` | `sandbox_mode`、`approval_policy`、`[mcp_servers.*]`、`[features.network_proxy]`、`web_search`、`[projects.*] trust_level` | `codex sandbox`、`codex --help`、配置 diff |
| Claude Code | `~/.claude/settings.json`、`.claude/settings.json(.local)`、managed settings、`~/.claude.json` | env（base_url）、hooks、permissions、MCP 信任、ConfigChange hooks | `/permissions`、`claude` 内审阅提示 |
| DSH | `~/.dsh/`（当前版本可能只有 patch/skin 与 `AGENTS.md` 软链） | `AGENTS.md` 指向、插件/皮肤来源、无隐式 profile 覆盖 | 启动日志、配置目录 diff |
| Hermes | `~/.hermes/config.yaml` | `approvals.mode`、model base_url、plugins、platforms | 配置文件核对、启动输出 |
| Kimi Code | `~/.kimi-code/`（以本机实际为准） | 指令文件、MCP/工具、网关 | 实际目录与版本核对 |

**接线核对**：`~/.codex/skills`、`~/.claude/skills`、`~/.hermes/skills`、`~/.agents/skills` 不保证指向同一目录；逐项看软链来源，不要假设「装一次全宿主都有」。

## Codex

官方两层控制：

- `sandbox_mode`（能做什么）：`read-only` / `workspace-write` / `danger-full-access`；默认 `workspace-write` 且网络关闭。
- `approval_policy`（何时必须问）：常用 `on-request`；`never` 仅在完全受控的隔离环境使用。

加固要点：

- `workspace-write` 下 `<root>/.git`、`.agents`、`.codex`、`.aws` 为受保护只读路径；保留这层，不要用 `--dangerously-bypass-approvals-and-sandbox`（别名 `--yolo`）。
- 需要出网时用 `[features.network_proxy]` 的域名 allow/deny，或 `[sandbox_workspace_write] network_access = true`（后者更宽，慎用）。
- `[projects."/path"] trust_level = "untrusted"` 收紧陌生目录。
- `approvals_reviewer = "auto_review"` 可做审批复核；`[otel]` 导出工具调用做审计（注意 `log_user_prompt`）。
- 机器级配置优先于项目级；团队可下发 managed `requirements.toml`。检查 `~/.codex/config.toml` 是否有陌生 `[mcp_servers.*]`——这是公开攻击的持久化点。
- 用 `codex sandbox macos|linux|windows` 本地验证沙箱行为；Dev Container 里 `danger-full-access` 会暴露容器内凭据。

依据：https://learn.chatgpt.com/docs/agent-approvals-security

## Claude Code

官方要点：

- 权限模式：manual（起始只读）/auto；`/permissions` 可审计与调整。
- 沙箱 bash：文件系统与网络隔离；`curl`/`wget` 等网络命令默认不自动批准。
- working directory boundary、workspace trust dialog；项目 `.mcp.json` 的 server 需单独批准。
- ConfigChange hooks 可审计/阻断设置变更；凭据存 Keychain 或 0600 文件。
- 处理不可信内容：先审命令、不要把不可信内容直接 pipe 给 agent、核对关键文件改动、必要时用 VM。

加固要点：

- 不把 `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` 改成非官方网关；检查项目 `.claude/settings.json` 的 `env`。
- 不接受陌生仓库的 `permissions.defaultMode = bypassPermissions/acceptEdits`、hooks、`enableAllProjectMcpServers`。
- 检查 `~/.claude.json` 的 `mcpServers`；定期 `/permissions` 看宽泛 Bash allow 规则。

依据：https://code.claude.com/docs/en/security

## DSH / Hermes / Kimi

- DSH：当前机器 `~/.dsh` 没有 `config.json/config.yml`，只有 `cordis.patch.yml` 与 `AGENTS.md` 软链；重点核对 `AGENTS.md` 指向是否可信目录、是否从 Downloads 加载。宿主机制以当前版本实际配置为准。
- Hermes：检查 `~/.hermes/config.yaml` 的 `approvals.mode`（`off` 等于不询问）、model base_url、plugins 与 platforms。`off` 只应在隔离环境；要改先备份并取得授权。
- Kimi Code：只确认 `~/.kimi-code` 存在；未核实其配置结构前不要断言具体字段，按「指令文件 + 网关 + MCP」三类通用入口检查。

## 供应链加固

- 第三方技能包：固定到 commit ref 并记录目录指纹；接入前跑 `scripts/verify_external_skills.py` 核对来源、roster 与逐目录指纹；更新时重新 materialize，不手工改 receipt。宿主侧只把通过核对的内容软链进技能目录。
- npm：提交 `package-lock.json`，CI 用 `npm ci`；陌生仓库先 `npm install --ignore-scripts`，再单独审生命周期脚本。
- Python：锁定版本与哈希（`pip-compile --generate-hashes` 或等价），拒绝 `--extra-index-url`/`--trusted-host`。
- 校验来源：npm `provenance`/sigstore、OpenSSF Scorecard、发布者身份与仓库来源；下载二进制核对哈希。
- CI：避免 `pull_request_target` 下检出并执行 PR 代码；`permissions` 最小化；secrets 只给必要 job。
- MCP：只接来源可验证的 server，最小 scope，不把长期 token 透传给 server。

## 快速核对命令

```bash
grep -nE '^\[mcp_servers|approval_policy|sandbox_mode|trust_level' ~/.codex/config.toml 2>/dev/null
grep -nE 'ANTHROPIC_BASE_URL|OPENAI_BASE_URL|hooks|defaultMode|mcpServers' \
  ~/.claude/settings.json ~/.claude/settings.local.json ~/.claude.json 2>/dev/null
grep -nE 'approvals|base_url|mcp' ~/.hermes/config.yaml 2>/dev/null
```

发现改动先备份原文件、记录 diff，再按授权修改；改完用 `agent_security_scan.py` 复扫。
