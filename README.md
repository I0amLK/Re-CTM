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
# 可选：不设置时，re-ctm serve 会自动生成 OAuth authorization key 并打印到本机终端。
# export RE_CTM_OAUTH_PASSWORD='请换成你自己的登录密码'

export RE_CTM_WORKSPACE="$HOME/re-ctm-workspace"
export RE_CTM_DATA_ROOT="$HOME/.re-ctm"
export RE_CTM_PRIVATE_ROOT="$HOME/.re-ctm/private"
export RE_CTM_DEBUG_ROOT="$HOME/.re-ctm/debug"

export RE_CTM_NATIVE_MODE=safe
export RE_CTM_NATIVE_EXEC_BACKEND=disabled
export RE_CTM_LATEX_POLICY=required
```

`RE_CTM_SERVER_URL` 不是必填项。未设置时，只要 Re-CTM 绑定在 loopback（例如 `127.0.0.1`），它会根据实际请求的 Host 和可信的本机反向代理头自动确定 OAuth issuer/resource。这适合 Cloudflare Quick Tunnel。

如果你有固定公网域名，可以显式固定 OAuth origin：

```bash
export RE_CTM_SERVER_URL=https://re-ctm.example.com
```

显式值始终优先，不会被 `X-Forwarded-Host` 覆盖。

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

浏览器打开 Re-CTM 授权页面后，输入启动终端显示的 `Re-CTM OAuth authorization key`。如果你显式设置了 `RE_CTM_OAUTH_PASSWORD`，则输入你设置的值。

授权完成后，网页客户端即可使用 Re-CTM。

如果网页客户端运行在另一台机器，不能把 `127.0.0.1` 作为客户端地址。可以直接使用 Cloudflare Quick Tunnel，并且**不需要先知道公网 URL，也不需要设置 `RE_CTM_SERVER_URL`**：

```bash
PORT=54567

fuser -k -9 ${PORT}/tcp 2>/dev/null || true

env -u RE_CTM_SERVER_URL -u RE_CTM_OAUTH_PASSWORD \
  RE_CTM_NATIVE_MODE=dangerous \
  re-ctm serve --host 127.0.0.1 --port ${PORT} &
MCP_PID=$!

sleep 2

cloudflared tunnel --url http://127.0.0.1:${PORT}
```

Re-CTM 启动后会在本机终端打印类似：

```text
Re-CTM OAuth authorization key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

这串 key 是 Re-CTM 首次 OAuth 授权页面的登录凭据，不是 Cloudflare Tunnel Token。Cloudflare Quick Tunnel 只负责给你公网 HTTPS URL。

建议把启动 Re-CTM 的终端保留在当前窗口中，直到首次 OAuth 授权完成，方便随时核对这串 authorization key 和服务日志。

`cloudflared` 打印出类似下面的地址后：

```text
https://abc-def.trycloudflare.com
```

网页 MCP 地址就是：

```text
https://abc-def.trycloudflare.com/mcp
```

Re-CTM 会在这个经 loopback tunnel 进入的请求上自动发布同一个 HTTPS OAuth issuer/resource，并把签发的 access token 绑定到该公网 origin。

如果使用 Cloudflare Named Tunnel 或其他固定域名，仍建议显式设置：

```bash
export RE_CTM_SERVER_URL=https://re-ctm.example.com
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

### 7.1 旧 CTM 工具兼容

Re-CTM 保留旧 CTM 的完整 18 个 Native 工具，因此原来依赖 CTM 的普通工作流不需要再单独启动 CTM：

```text
server_info
check_exec_environment
read_file
list_dir
list_files
search_text
apply_patch
exec_command
write_stdin
kill_command
read_output
git_status
git_diff
git_log
git_show
git_blame
request_permissions
view_image
```

数学侧对网页客户端只暴露 6 个高层 `rethlas_*` 工具，因此正常 `tools/list` 一共是 **24 个工具**：18 个 CTM Native + 6 个 Rethlas façade。

```text
rethlas_start
rethlas_step
rethlas_inspect
rethlas_retrieve
rethlas_control
rethlas_artifact
```

旧版 Re-CTM 的 `rethlas_next/read/write/search/commit/status/steer/resume/cancel/get_artifact/export_final` 调用仍由服务器接受，作为隐藏兼容入口，但不再出现在 `tools/list` 中，避免模型在大量内部协议工具之间反复选择。

原来 CTM 的长命令生命周期也继续使用。例如网页模型启动一个耗时测试后，可以得到 `command_id`，随后继续等待输出、读取保留输出、向 TTY 程序输入内容，或者终止进程。实际使用时仍然直接用自然语言即可，例如：

```text
运行测试；如果十秒内没有结束就继续监控输出，结束后告诉我失败项。
```

```text
启动这个需要交互的终端程序，等它出现提示后输入 yes。
```

```text
如果刚才的命令还没有结束，停止它。
```

需要 `exec_command`、`write_stdin`、`kill_command` 这组完整生命周期功能时，Linux 上推荐按下一节启用 Bubblewrap backend。

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

连接器读取 Re-CTM 的 MCP instructions 后，遇到具体的数学证明、推导、证明修复或严格验证任务时，应优先启动 Rethlas workflow，而不是直接在聊天中给出未经 workflow 验证的证明。只有你明确要求“直接给出非正式回答，不使用 Rethlas”时，客户端才应跳过该流程。

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

默认最终文件会自动写到：

```text
rethlas-output/<run_id>/proof_verified.tex
```

也可以在开始任务时指定另一个 workspace-relative `.tex` 路径，例如：

```text
使用 Rethlas 证明下面的问题，并把最终验证通过的 LaTeX 写到 results/group-pushout.tex。
```

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

当最后一次 `rethlas_step` 把任务推进到 `done` 时，Re-CTM 会通过受控 final-artifact bridge 自动把验证后的 LaTeX 写进 workspace，并在返回结果中提供 `workspace_export_path`。默认路径是：

```text
rethlas-output/<run_id>/proof_verified.tex
```

任务完成后仍可以说：

```text
给我这个 run 的最终 verified LaTeX。
```

这会读取已经机械 finalization 的 `final_tex` artifact；它不再是把文件落盘所必需的额外步骤。

如果希望把同一份最终文件另外导出到其他路径，可以说：

```text
把最终 proof_verified.tex 导出到 workspace 的 result/proof_verified.tex。
```

自动默认导出是幂等的：重复取得 `done` 状态时，如果文件内容完全相同，不会重复改写。若自动目标路径已有不同内容，Re-CTM 不会覆盖它；显式导出到已有目标时仍要求当前文件的 SHA-256 baseline。

对已经完成但尚未落盘的旧 run，可以直接要求“把这个 run 的最终文件写到默认位置”；当前公开入口是 `rethlas_artifact` 的 `export` 动作，省略路径时会使用该 run 的 `workspace_export_path`。旧 `rethlas_export_final` 名称仍作为隐藏兼容入口接受。

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
export RE_CTM_OAUTH_PASSWORD='你的 OAuth 密码'  # 独立烟测建议显式设置，方便脚本读取
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

然后确认网页客户端确实能够访问你提供给它的公网 MCP 地址。

如果没有设置 `RE_CTM_SERVER_URL`，确认 Re-CTM 是以 `--host 127.0.0.1` 或其他 loopback 地址启动，并确认 tunnel/reverse proxy 把公网 Host（以及通常的 `X-Forwarded-Proto: https`）转发到本机服务。

### 网页客户端不在本机

客户端不能连接 `127.0.0.1`，但 Re-CTM 服务本身仍建议绑定 `127.0.0.1`。使用 Cloudflare Quick Tunnel 时不必设置 `RE_CTM_SERVER_URL`；使用固定公网域名时再把 `RE_CTM_SERVER_URL` 设置为该 HTTPS origin。

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
