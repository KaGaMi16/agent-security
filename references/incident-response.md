# 处置流程：疑似被投毒 / 已被触发

适用：看到可疑 AGENTS.md、发现陌生 MCP 配置、base_url 被改、token 可能外泄、agent 执行了看不懂的命令。目标顺序是**先止损、再留证、后清理、最后轮换与复核**。删除、改配置、轮换凭据都属于用户授权动作，脚本本身只读。

## 0. 前提

- 假定凭据可能已泄露，但不要自行判定「哪个泄露了」——列出候选让用户确认。
- 不要先删可疑文件：那会毁掉证据，也看不出攻击面。
- 不确定时先在隔离环境（VM/只读挂载）操作，不在原机继续运行 agent。

## 1. 止损

1. 结束相关 agent 会话/进程（Codex、Claude Code、DSH、Hermes、IDE 内 agent）。
2. 暂停在该目录的后续命令；如果怀疑本机被持久化，断开自动同步/远程访问，必要时断网（会打断你取证，先决定）。
3. 通知用户：当前状态、已做动作、下一步需要授权的项。

## 2. 留证

先保存，再动文件：

```bash
mkdir -p ~/agent-security-incident-$(date +%Y%m%d-%H%M%S)/evidence
```

保存内容：

- 两份扫描的完整 JSON：`agent_security_scan.py --format json > scan-host.json`、`scan_untrusted_tree.py <dir> --format json > scan-tree.json`。
- 可疑文件副本及哈希：`shasum -a 256`；配置文件改前原值。
- 时间线：`ls -lT`、`stat`、shell 历史相关片段（`~/.zsh_history` 或 `~/.bash_history`）。
- 进程与服务：`ps aux`、`launchctl list`、`crontab -l`、`ls ~/Library/LaunchAgents`、`ls ~/.config/systemd/user`。
- 已安装包：`npm ls -g --depth=0`、`pip list`。
- 网络侧（可做时）：最近连接、代理设置、DNS 变更。
- 会话记录/日志：宿主 session log、OTel/审计日志（如有）。

## 3. 清点（四类入口）

1. **指令文件**：`~/Downloads`、`~/Desktop`、`/tmp`、项目根/子目录的 `AGENTS.md`/`CLAUDE.md`/`.cursorrules`/README 异常改动；查零宽字符。
2. **配置持久化**：`~/.codex/config.toml` 的 `[mcp_servers.*]`、`approval_policy`、`sandbox_mode`；`.claude/settings.json` 的 env/hooks/permissions；`.mcp.json`；DSH/Hermes/Kimi 配置；shell profile 的 alias/export。
3. **依赖与启动项**：`/tmp/ptools`、`function-color`/`function-flag`（npm 全局与缓存）、LaunchAgents/LaunchDaemons、cron、systemd user unit、登录项。
4. **代理劫持**：`ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`/`base_url`、`NODE_OPTIONS`、`DYLD_INSERT_LIBRARIES`/`LD_PRELOAD`、`BASH_ENV`、`GIT_SSH_COMMAND`、`NODE_TLS_REJECT_UNAUTHORIZED=0`。

每条记录：位置、原始内容、首次出现时间（能从 git/备份/日志推出就写）、是否你自己配置。

## 4. 清除（需授权，先备份）

1. 把要改/删的文件先复制到证据目录并记录哈希；配置改前另存 `.bak-<时间>`。
2. 移除陌生 MCP server 条目、hooks、env 覆盖、base_url、可疑 alias/export；恢复你自己的已知良好配置。
3. 卸载可疑包：`npm uninstall -g function-color`、清缓存相关条目；不要盲目 `rm -rf` 整个 npm 缓存（先备份索引再清）。
4. 移除 LaunchAgents/systemd/cron 项（先 `launchctl unload`/`systemctl --user disable`，再删文件）。
5. 删除投毒指令文件；若来自网页自动下载，检查浏览器下载记录与来源域名。
6. 改完复扫；把「已清除/仍残留/未知」分开写。

## 5. 凭据轮换（假定泄露）

| 凭据 | 动作 |
| --- | --- |
| Anthropic / OpenAI API key | 控制台撤销旧 key，签发新 key；检查用量异常 |
| Claude OAuth / 其他会话 token | 退出所有设备、撤销会话、重新登录 |
| GitHub PAT / SSH key / deploy key | 撤销 token、删旧 key、重新生成；查审计日志与新增仓库/webhook |
| npm token | 撤销并重发；检查近期 publish 与包版本 |
| AWS/GCP/Azure 等云凭据 | 轮换 access key、检查 IAM 变更与异常调用 |
| SSH 私钥 | 生成新密钥对、替换 `authorized_keys`、检查登录日志 |
| CI/CD secrets、webhook、Slack/飞书 token | 轮换并检查近期变更 |
| 浏览器 cookie / 密码库 | 视暴露面决定；至少改关键账户密码并开 2FA |

轮换后再确认：旧 token 已失效、没有新设备/新 key 残留、用量恢复正常。

## 6. 验证

1. 重跑 `agent_security_scan.py` 与项目预检，高危应为 0（或明确解释为什么保留）。
2. 检查配置 diff：只剩你确认过的值。
3. 检查持久化：LaunchAgents/systemd/cron 无未知项。
4. 观察一段时间：异常出网、异常 npm publish、异常登录、模型用量突增。
5. 结论写清证据、已做动作、仍未知项；不要把「扫描无告警」当作已恢复。

## 7. 复盘

- 根因：投递怎么进来的（网页下载、clone、依赖、他人分享）？
- 哪个环节本可以拦住（不在 Downloads 启动、审批、沙箱、网络白名单）？
- 更新本机基线：清理下载目录、固定启动目录、收紧审批、复跑自检。
- 记录 IoC 与时间线，便于下次比对。

## 边界

本流程是「个人/小团队可执行的处置顺序」，不替代专业 IR/取证；涉及公司资产、生产系统、合规上报时按组织流程走，并保留原始证据链。
