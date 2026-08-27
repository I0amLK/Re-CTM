# Re-CTM

Re-CTM 是一个通过网页 MCP 客户端使用的本地服务。安装后只需要运行一个 Re-CTM，不需要另外安装 Rethlas，也不需要目标电脑安装 Codex。

最终数学任务的正式交付物是：

```text
proof_verified.tex
```

## 1. 系统要求

推荐环境：

- Linux
- Python 3.11 或更高版本
- 支持 OAuth MCP 的网页客户端
- 如果需要 `exec_command`：安装 `bubblewrap`（命令通常为 `bwrap`）
- 如果需要正式 LaTeX 编译验收：安装 `latexmk` 和可用的 TeX Live/LaTeX 环境

Ubuntu/Debian 可先安装：

```bash
sudo apt update
sudo apt install -y python3 python3-venv bubblewrap latexmk texlive-latex-base texlive-latex-recommended texlive-latex-extra
```

如果只想先连接网页并使用文件读取、搜索和修改功能，`latexmk` 可以稍后安装。

## 2. 安装 Re-CTM

使用 uv：

```bash
uv tool install git+https://github.com/I0amLK/Re-CTM.git
```

升级：

```bash
uv tool upgrade re-ctm
```

或者使用 pipx：

```bash
pipx install git+https://github.com/I0amLK/Re-CTM.git
```

升级：

```bash
pipx upgrade re-ctm
```

安装后确认：

```bash
re-ctm --help
```

## 3. 准备工作目录和数据目录

这两个目录必须互相分开。

```bash
mkdir -p ~/re-ctm-workspace
mkdir -p ~/.re-ctm
```

`~/re-ctm-workspace` 是网页模型可以操作的目录。

`~/.re-ctm` 是 Re-CTM 保存任务状态、验证信息和内部数据的目录。不要把它放进 workspace 里面。

## 4. 最小配置

```bash
export RE_CTM_SERVER_URL=http://127.0.0.1:8765
export RE_CTM_OAUTH_PASSWORD='请换成你自己的登录密码'

export RE_CTM_WORKSPACE="$HOME/re-ctm-workspace"
export RE_CTM_DATA_ROOT="$HOME/.re-ctm"
export RE_CTM_PRIVATE_ROOT="$HOME/.re-ctm/private"
export RE_CTM_DEBUG_ROOT="$HOME/.re-ctm/debug"

export RE_CTM_NATIVE_MODE=safe
export RE_CTM_NATIVE_EXEC_BACKEND=disabled
export RE_CTM_LATEX_POLICY=required
```

检查配置：

```bash
re-ctm check-config
```

输出中出现 `"ok": true` 即表示基础配置通过。

## 5. 启动服务

```bash
re-ctm serve --host 127.0.0.1 --port 8765
```

也可以使用环境变量：

```bash
export RE_CTM_HOST=127.0.0.1
export RE_CTM_PORT=8765
re-ctm serve
```

网页 MCP 地址：

```text
http://127.0.0.1:8765/mcp
```

OAuth 元数据地址：

```text
http://127.0.0.1:8765/.well-known/oauth-protected-resource
```

## 6. 在网页 MCP 客户端中连接

在支持远程或自定义 MCP 的网页客户端中新增 MCP Server：

```text
http://127.0.0.1:8765/mcp
```

客户端应自动进入 OAuth 注册和授权流程。

浏览器打开 Re-CTM 授权页面后，输入 `RE_CTM_OAUTH_PASSWORD` 对应的密码。

授权完成后，网页客户端即可使用 Re-CTM。

如果网页客户端运行在另一台机器，不能使用 `127.0.0.1`。需要先把 Re-CTM 通过 HTTPS 暴露给该客户端，例如：

```bash
export RE_CTM_SERVER_URL=https://re-ctm.example.com
```

网页 MCP 地址改为：

```text
https://re-ctm.example.com/mcp
```

## 7. 普通电脑操作

连接后直接在网页对话中用自然语言操作 workspace，例如：

```text
读取 workspace 里的 main.tex，并告诉我文件结构。
```

```text
搜索所有包含 theorem 的文件。
```

```text
把 notes.tex 中这一段修改成我给你的内容。
```

```text
列出 workspace 中所有 tex 文件。
```

这些操作都只针对 `RE_CTM_WORKSPACE`。

## 8. Native 权限模式

默认建议：

```bash
export RE_CTM_NATIVE_MODE=safe
```

本地开发可以使用：

```bash
export RE_CTM_NATIVE_MODE=trusted
```

需要最大普通电脑工具权限时可以使用：

```bash
export RE_CTM_NATIVE_MODE=dangerous
```

`dangerous` 只扩大普通电脑工具权限，不会跳过 Rethlas 数学验证步骤，也不会让普通电脑工具直接读取 Rethlas 私有任务状态。

## 9. 启用 exec_command

默认：

```bash
export RE_CTM_NATIVE_EXEC_BACKEND=disabled
```

此时文件读取、搜索和修改仍然可用，但执行任意命令会被拒绝。

Linux 上先确认 Bubblewrap：

```bash
bwrap --version
```

再运行：

```bash
re-ctm attest-native \
  --backend bubblewrap \
  --workspace "$HOME/re-ctm-workspace" \
  --data-root "$HOME/.re-ctm" \
  --private-root "$HOME/.re-ctm/private"
```

如果这里通过，从源码仓库继续运行完整隔离测试：

```bash
python3 scripts/manual_native_isolation_test.py \
  --backend bubblewrap \
  --workspace "$HOME/re-ctm-workspace" \
  --data-root "$HOME/.re-ctm" \
  --private-root "$HOME/.re-ctm/private" \
  --output native-isolation-validation.json
```

确认报告包含：

```json
"passed": true
```

再设置：

```bash
export RE_CTM_NATIVE_EXEC_BACKEND=bubblewrap
export RE_CTM_NATIVE_ISOLATION_ATTESTED=1
```

然后重新启动 Re-CTM。

## 10. 使用 Rethlas 数学模式

不需要单独下载或启动 Rethlas。

直接在网页中说：

```text
使用 Re-CTM 的 Rethlas 工作流证明下面的定理。
最终只需要给我经过验证的 LaTeX。

<这里粘贴数学问题>
```

也可以先把问题放在 workspace，例如 `problem.tex`，然后说：

```text
读取 workspace/problem.tex，然后启动 Rethlas 工作流证明这个问题。
```

启动后请保留返回的 `run_id`。后续查看进度、恢复、干预和取最终结果都使用同一个 `run_id`。

## 11. 查看数学任务进度

可以直接问：

```text
查看这个 Rethlas 任务当前进行到哪里。
```

```text
告诉我当前有哪些证明方案，以及哪些分支已经完成。
```

## 12. 中途给证明方向

例如：

```text
这个任务后续优先尝试代数方法，不要继续沿用刚才失败的组合论路线。
```

指导会在后续合适阶段进入任务。

## 13. 网页断开后恢复

重新连接同一个 Re-CTM 后说：

```text
恢复 run_id 为 <你的 run_id> 的 Rethlas 任务。
```

## 14. 取消数学任务

```text
取消 run_id 为 <你的 run_id> 的 Rethlas 任务。
```

## 15. 数学检索

默认 theorem retrieval 地址：

```text
https://leansearch.net/api/search
```

可覆盖：

```bash
export RE_CTM_THEOREM_SEARCH_URL=https://leansearch.net/api/search
export RE_CTM_THEOREM_SEARCH_TIMEOUT_SECONDS=30
```

网页中可以说：

```text
在这个 Rethlas 任务中搜索与当前关键引理有关的外部数学结果，并核对适用条件。
```

外部搜索结果只是待核验资料，不应自动视为正确证明。

## 16. 获取最终 proof_verified.tex

任务完成后说：

```text
给我这个 run 的最终 verified LaTeX。
```

如果希望把最终文件写进 native workspace，可以说：

```text
把最终 proof_verified.tex 导出到 workspace 的 result/proof_verified.tex。
```

如果目标文件已经存在，Re-CTM 会要求当前文件的 SHA-256 baseline 后才能覆盖。

## 17. LaTeX 模式

正式使用推荐：

```bash
export RE_CTM_LATEX_POLICY=required
```

需要安装：

```text
bubblewrap
latexmk
TeX Live / LaTeX
```

仅调试流程时可以使用：

```bash
export RE_CTM_LATEX_POLICY=static_only
```

`static_only` 不建议作为正式数学结果的最终验收方式。

## 18. 查看服务状态

```bash
curl http://127.0.0.1:8765/health
```

配置检查：

```bash
re-ctm check-config
```

源码仓库的本地检查：

```bash
python3 scripts/run_local_checks.py
```

## 19. OAuth / MCP 独立烟测

服务已经启动时，在源码仓库运行：

```bash
export RE_CTM_OAUTH_PASSWORD='你的 OAuth 密码'
python3 scripts/smoke_oauth_mcp.py \
  --base-url http://127.0.0.1:8765 \
  --output oauth-mcp-smoke.json
```

成功时报告包含：

```json
"passed": true
```

报告不会保存 OAuth 密码、授权码、Access Token 或 Client Secret 原文。

## 20. Debug

建议：

```bash
export RE_CTM_DEBUG=1
export RE_CTM_TRACE_PAYLOADS=0
```

出现错误时先保存工具返回的 `trace_id`。

有 `run_id` 时可以在源码仓库生成诊断包：

```bash
python3 scripts/collect_debug_bundle.py <run-id> \
  --data-root "$HOME/.re-ctm" \
  --output debug-bundle.json
```

诊断包不会包含问题正文、证明正文或 OAuth Secret 原文。

## 21. 常见问题

### `NATIVE_ISOLATION_REQUIRED`

说明 `exec_command` 尚未启用隔离。按照第 9 节完成 Bubblewrap 验证。

### `TRUST_DOMAIN_OVERLAP`

说明 workspace 与 data/private 目录互相包含。把它们移动到两个互不包含的目录。

### OAuth 页面打不开

先运行：

```bash
curl http://127.0.0.1:8765/health
```

然后确认网页客户端确实能够访问 `RE_CTM_SERVER_URL`。

### 网页客户端不在本机

不要使用 `127.0.0.1`。配置一个该网页客户端可以访问的 HTTPS 地址，并让 `RE_CTM_SERVER_URL` 与外部地址完全一致。

### LaTeX 一直返回 repair

检查：

```bash
bwrap --version
latexmk -v
```

并确认证明是完整、单文件、自包含的 `.tex`。

## 22. 最终人工验收

真实网页客户端、最终目标 PC，以及“Rethlas 核心方法论达到约 95% 功能等价”的最终结论，需要按照：

```text
manual-validation.json
```

在实际部署环境中手动验收。

更完整的服务器部署步骤见：

```text
docs/DEPLOYMENT.md
```
