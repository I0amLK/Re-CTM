# Re-CTM

Re-CTM 是一个通过网页 MCP 客户端使用的本地服务。安装后只需要运行一个 Re-CTM，不需要另外安装 Rethlas，也不需要目标电脑安装 Codex。

当前源码版本：**Re-CTM v0.4.1**，修复 Native 异步命令随 HTTP 请求线程结束而被终止的问题。新候选须完成目标机验收；历史发布验收不代表本次源码已发布。

当前源码已加入基于 MTM 的兼容性更新：无损文件分页、workspace 内多 Git 仓库选择、并发密钥初始化、`/mcp` OAuth 资源发现、简洁/详细 TUI 和 LaTeX 字面文本检查。变更范围、兼容边界与验收限制见 [MTM 功能移植说明](docs/MTM_BACKPORT.md)。这不是新的已发布或目标机验收版本。经用户批准，当前源码进一步迁移到 MTM v11 的 25 工具契约、protocol 3 与新状态格式；升级差异和安全边界见 [MTM 契约迁移说明](docs/MTM_MIGRATION.md)。

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

已有本机验收通过的 0.4.1 隔离安装时，可使用[可回滚的短命令激活](docs/DEPLOYMENT.md#accepted-local-launcher)替换旧的 PATH 入口，无需重新安装或每次输入长环境命令。

安装后确认：

```bash
re-ctm --help
```

## 3. 准备工作目录和数据目录

Re-CTM 可以直接把你当前打开终端所在的项目目录作为 workspace。先 `cd` 到你希望网页模型操作的目录；不要在 `$HOME` 或 `/` 直接启动。

```bash
mkdir -p ~/.re-ctm
export RE_CTM_WORKSPACE="$PWD"
```

`$PWD` 是网页模型可以操作的目录。

`~/.re-ctm` 是 Re-CTM 保存任务状态、验证信息和内部数据的目录。不要把它放进 workspace 里面。

## 4. 最小配置

```bash
# 可选：不设置时，re-ctm serve 会自动生成 OAuth authorization key 并打印到本机终端。
# export RE_CTM_OAUTH_PASSWORD='请换成你自己的登录密码'

export RE_CTM_WORKSPACE="$PWD"
export RE_CTM_DATA_ROOT="$HOME/.re-ctm"
export RE_CTM_PRIVATE_ROOT="$HOME/.re-ctm/private"
export RE_CTM_DEBUG_ROOT="$HOME/.re-ctm/debug"

export RE_CTM_NATIVE_MODE=dangerous
export RE_CTM_LATEX_POLICY=required

# 可选：仅当某个 CLI 工具链的依赖目录无法从 PATH/symlink 自动推断时使用。
# export RE_CTM_NATIVE_EXEC_ALLOW_ROOTS="/opt/vendor-suite:/srv/shared-math-runtime"
```

Linux 上如果安装了 `bwrap`，Re-CTM 会自动选择内置 Bubblewrap 执行后端并在每次启动时做 fail-closed 隔离自检；不需要额外设置 `RE_CTM_NATIVE_EXEC_BACKEND` 或 `RE_CTM_NATIVE_ISOLATION_ATTESTED=1`。如果没有可用的 Bubblewrap，任意命令执行仍会保持关闭。

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

如果你是在目标项目文件夹中直接打开终端，推荐交互式使用：

```bash
re-ctm tui
```

`re-ctm tui` 与 `serve` 使用同一套 OAuth/MCP 服务，只额外增加一个本地、追加式的终端观察层。它会显示当前 workspace、可用的 MCP URL、自动生成的 OAuth authorization key（如果密码由环境变量显式配置则只显示 `configured externally`）、OAuth 连接状态，以及每次 MCP tool call 的工具名和成功/失败。它不轮询数据库或日志文件，不显示工具参数/结果正文，也不统计或估算模型 token。

默认模式每次工具调用只显示一行开始提示，另行显示失败或需要修正的 workflow submission；普通成功完成行不再重复刷屏。排障时用 `re-ctm tui --verbose` 显示完成行与 trace 标识。两种模式都不显示参数值、结果正文或 capability。

无界面/headless 部署继续使用原命令：

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

以 `/mcp` 作为 OAuth resource 的客户端也可以使用 `/.well-known/oauth-protected-resource/mcp`。新路径声明完整的 MCP URL，issuer 仍为 origin；旧 origin 资源和旧 token audience 保持兼容，其他路径或其他 origin 不会被接受。

如果网页客户端不在本机，且已经安装 `cloudflared`，推荐直接使用一条命令启动临时公网入口：

```bash
re-ctm tui --quick-tunnel --native-mode dangerous
```

`--quick-tunnel` 会先成功绑定本地 loopback MCP，再启动一个只属于本次 TUI 会话的 Cloudflare Quick Tunnel，并在拿到真实随机地址后显示：

```text
Public MCP URL https://<random>.trycloudflare.com/mcp
```

如果没有显式 `--port`，也没有设置 `RE_CTM_PORT`，Quick Tunnel 模式会让操作系统自动选择空闲 loopback 端口，所以不需要再运行 `fuser -k -9`。显式端口和 `RE_CTM_PORT` 仍然优先。`--quick-tunnel` 会为本会话使用动态 OAuth origin，即使环境里存在旧的 `RE_CTM_SERVER_URL`；它不会修改环境变量或持久化配置。

Quick Tunnel 是显式可选功能：普通 `re-ctm tui` 和 `re-ctm serve` 都不会检测或启动 `cloudflared`。如果 `cloudflared` 不存在或启动失败，本地 Re-CTM 服务仍保持运行并显示本地 MCP URL。TUI 只接受真实的 HTTPS `*.trycloudflare.com` 地址，不自动安装 `cloudflared`，也不支持 named tunnel/account token 管理。

## 6. 在网页 MCP 客户端中连接

在支持远程或自定义 MCP 的网页客户端中新增 MCP Server：

```text
http://127.0.0.1:8765/mcp
```

客户端应自动进入 OAuth 注册和授权流程。

浏览器打开 Re-CTM 授权页面后，输入启动终端显示的 `Re-CTM OAuth authorization key`。如果你显式设置了 `RE_CTM_OAUTH_PASSWORD`，则输入你设置的值。

授权完成后，网页客户端即可使用 Re-CTM。

如果网页客户端运行在另一台机器，不能把 `127.0.0.1` 作为客户端地址。最简单的方式是：

```bash
re-ctm tui --quick-tunnel --native-mode dangerous
```

Re-CTM 会在同一个终端显示自动生成的 OAuth authorization key、本地地址和随机公网 MCP URL。例如：

```text
OAuth key      xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Public MCP URL https://abc-def.trycloudflare.com/mcp
```

这串 key 是 Re-CTM 首次 OAuth 授权页面的登录凭据，不是 Cloudflare Tunnel Token。Cloudflare Quick Tunnel 只负责给你公网 HTTPS URL。

如果你需要手工管理 tunnel 或排查 `cloudflared`，原来的两进程方式仍然可用：先运行 `re-ctm tui --port <PORT>` 或 `re-ctm serve --host 127.0.0.1 --port <PORT>`，再在另一个终端执行 `cloudflared tunnel --url http://127.0.0.1:<PORT>`。

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

### 7.1 MTM v11 Native 工具

当前源码提供 19 个 MTM Native 工具，包含原有 18 个工具与新增的 revision-bound `apply_changes`。这是新契约迁移，客户端应刷新工具 schema：

```text
server_info
check_exec_environment
read_file
list_dir
list_files
search_text
apply_patch
apply_changes
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

数学侧对网页客户端只暴露 6 个高层 `rethlas_*` 工具，因此正常 `tools/list` 一共是 **25 个工具**：19 个 MTM Native + 6 个 Rethlas façade。

```text
rethlas_start
rethlas_step
rethlas_inspect
rethlas_retrieve
rethlas_control
rethlas_artifact
```

旧版 `rethlas_next/read/write/search/commit/status/steer/resume/cancel/get_artifact/export_final` MCP 别名已退役，调用会被拒绝。客户端必须迁移到上面的六个 façade；持久化旧任务的恢复兼容与公开工具别名是两件独立的事。

`rethlas_step` 返回的当前任务现在是 **zero-guess contract**：模型不需要猜内部 JSON 结构。每个模型参与的 workflow state 都会明确给出 `write_contract`、`commit_action`、`commit_payload_schema`，以及一个最小合法 submission/template/example。Memory write 默认是一条 JSON object 记录；如果某一步由服务器从 commit payload 自动生成 canonical memory（例如 decomposition plans、failure summary、replan decision），task 会把 `write_contract` 明确设为空，避免客户端重复写同一流程事实。

如果某次 `rethlas_step` 的 write 或 commit 因 validation/conflict 需要修正，服务器会返回 `submission.recoverable=true`、`retryable=true` 和新的 capability。已经成功的逻辑 writes 会明确标记为 retained，客户端应继续使用新 capability，并且**不要重放 retained writes**。权限/安全错误仍然是 hard failure，不会被这个修正机制吞掉。

`capability` 是服务器签发的**不透明句柄**，不是客户端可编辑的 JSON/JWT 字段。每次提交都应从同一个当前 task envelope 原样复制 `run_id` 与 `capability`；不要解码、改写、规范化、拼接或自行构造 capability，也不要把某个 run 的 capability 与另一个 run 的 `run_id` 混用。服务器会在任何 logical write 发生前机械检查这两个 envelope 字段的绑定关系，并同时核对签名 claims 与持久化 capability registry 中的 run/domain/role/epoch/state/permissions/time facts。

`read_file` 的长行分页现在返回 `next_action.arguments`，其中包含同一行的字节偏移和文件 SHA-256；续读时原样使用这些参数，避免跳过或重复中文、emoji 等 UTF-8 内容。文件在两次读取之间变化会返回 conflict，需重新读取。五个 Git 工具新增可选 `repo_path`，可明确选择 workspace 内的子仓库；文件过滤路径相对于所选仓库，不能越出 workspace。完整示例见 [MTM 功能移植说明](docs/MTM_BACKPORT.md)。

六个 façade 的 typed JSON schema 也按 operation/action 分支收紧：无关但“已知”的字段不再被静默忽略，必需字段必须显式存在。例如 `rethlas_artifact` 的 run artifact 读取现在必须显式给出 `artifact`，避免依赖处理器内部默认值产生 schema 与运行语义漂移。

客户端处理结构化错误时以 `category` 和 `retryable` 为主，不要只猜错误字符串：`validation` 应修正请求；`conflict` 根据 `retryable` 选择协调状态或刷新后重试；`permission` / `security` 是 hard failure，不应拿同一 authority 自动重试；`not_found` 应刷新标识；`runtime` 仅在 `retryable=true` 时自动稍后重试；`internal` 应停止并报告。`rethlas_step` 只把当前 submission 内的 `validation` / `conflict` 转成带 fresh capability 的 recoverable correction，权限与安全错误不会进入该恢复路径。源码错误契约可用 `python3 scripts/audit_error_contract.py` 机械审计，避免手工维护第二份错误码表。

历史 **Re-CTM v0.2.0** 开始，这六个 façade 还共同提供 Verified Research Workspace：跨 run 的 project/claim registry、冻结的 project snapshot、`proof_manifest`、reference provenance/audit、paper-aware retrieval，以及不削弱 verifier 的 compact verified lane。当时 public tool 数量为 24；这些能力通过六个 Rethlas façade 的 typed operations 暴露。当前新契约因新增 `apply_changes` 而合计 25 个公开工具。

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

`exec_command` 必须只给 `argv` 或 `cmd` 其中一种。`argv` 直接传递程序与参数，`cmd` 使用非 login 的 `/bin/sh -c`。总运行期限默认 300000 ms、最大 600000 ms；首次等待仍默认 10000 ms。可显式提供 `env.PATH`，可执行文件检查与实际 sandbox 使用同一个 PATH 和 workspace-relative workdir。每次结果通过 `operation_outcome` 区分 running、exited_0、exited_nonzero、timeout 与 signal；非零子进程退出不会被误报为 MCP 传输失败。

`apply_changes` 支持 create/write/edit/delete/move/copy。修改已有文件前先 `read_file`，把同次读取返回的 `revision` 原样放入 change；move/copy 目标必须不存在。`dry_run` 不创建文件或目录。`apply_patch` 和 `apply_changes` 可使用 caller-scoped `idempotency_key`，但该内存回执不跨进程重启持久化。遇到 unknown outcome 或 rollback failure，应检查并协调文件，不能仅换一个 key 重试。完整限制见 [迁移说明](docs/MTM_MIGRATION.md)。

命令结束后还会返回 `termination` provenance。Re-CTM 会区分自身 command timeout、显式 `kill_command`、服务关闭，以及只能观察到外部 signal 的 `external_or_unknown`。例如程序收到 `SIGKILL` 而 Re-CTM 从未发送 KILL 时，结果不会猜测为 OOM，而会明确标记原因未知。这个诊断是 additive metadata，不改变原 CTM 的 timeout/TERM/KILL 生命周期语义。

需要 `exec_command`、`write_stdin`、`kill_command` 这组完整生命周期功能时，Linux 上推荐按下一节启用 Bubblewrap backend。

## 8. Native 权限模式

当前公开配置只支持 `dangerous`，且以它为默认值：

```bash
export RE_CTM_NATIVE_MODE=dangerous
```

升级前的 `safe` / `trusted` 配置会被拒绝，应在审核本次权限契约变化后修改配置。若不需要任意命令执行，可设置 `RE_CTM_NATIVE_EXEC_BACKEND=disabled`；不要把旧模式名称当作仍然生效的保护。

`dangerous` 不会跳过 OAuth、workspace/private-root 隔离、Rethlas capability、verifier 或 finalizer。执行后端仍必须通过硬隔离 attestation，LaTeX 固定 adapter 仍明确隔离网络。`request_permissions` 只返回兼容信息，不创建新的权限授权状态。

## 9. 启用 exec_command

Linux 上安装 Bubblewrap 后，Re-CTM 默认自动启用隔离的 `exec_command`：

```bash
bwrap --version
```

服务启动时会自动做隔离 attestation；失败则服务不会开放该执行后端。

公开 Native 使用 `dangerous`，硬隔离和工具链只读挂载仍独立生效。Re-CTM 不维护 Sage、Magma、Mathematica 等软件名单，而是使用统一的 **Native Toolchain Exposure Policy**：

```text
系统只读 roots
  ∪ PATH 自动发现的工具链 prefix
  ∪ executable symlink 的真实 target prefix
  ∪ RE_CTM_NATIVE_EXEC_ALLOW_ROOTS 显式 roots
        ↓ canonicalize / 去重 / ancestor collapse
        ↓ 拒绝 workspace、data root、private root 与过宽根目录
        ↓ Bubblewrap --ro-bind
```

`dangerous` 会继承经验证的宿主 PATH 并自动发现其中的非系统工具链。内部隔离 adapter 的模式不是公开配置选项。Conda/venv 的 `bin` 会提升到环境 prefix，普通 `bin`/`sbin`/`Executables` 会提升到产品 prefix，PATH 中的 symlink 会解析真实 target。整个过程不检查应用名称。

因此只要程序能从启动 Re-CTM 时的终端 PATH 找到，或其运行根通过显式 roots 声明，类似命令都可以通过同一机制执行：

```bash
sage -c 'print(2+3)'
magma
wolframscript -code '2+3'
python3 script.py
```

某些软件把可执行文件、库或数据库分散在 PATH 无法推断的目录中。这时使用 Linux 的 `:` 分隔绝对路径：

```bash
export RE_CTM_NATIVE_EXEC_ALLOW_ROOTS="/opt/Wolfram/Mathematica/15.0:/srv/shared-cas-runtime"
```

这些目录必须已经存在，不能是 `/`、完整 `$HOME`、`/home`、`/var`、`/opt` 等过宽聚合根，不能与 workspace、`~/.re-ctm` 或它们的祖先/后代重叠；应声明具体产品/运行时子目录，最终只读挂载。`re-ctm check-config` 与 `check_exec_environment` 会显示解析后的 toolchain exposure plan。

显式 roots 当前只由内置 Bubblewrap 后端实现；与 `RE_CTM_NATIVE_EXEC_BACKEND=external` 同时配置会直接拒绝启动，避免第三方 helper 静默忽略目录。

Re-CTM 的 data/private roots 不会因为 `dangerous` 被挂进执行环境。你仍可以手工检查隔离状态：

```bash
re-ctm attest-native \
  --backend bubblewrap \
  --workspace "$PWD" \
  --data-root "$HOME/.re-ctm" \
  --private-root "$HOME/.re-ctm/private" \
  --allow-root /opt/vendor-suite
```

没有显式 roots 时删去 `--allow-root`；有多个时重复该参数。

如果这里通过，从源码仓库继续运行完整隔离测试：

```bash
python3 scripts/manual_native_isolation_test.py \
  --backend bubblewrap \
  --workspace "$PWD" \
  --data-root "$HOME/.re-ctm" \
  --private-root "$HOME/.re-ctm/private" \
  --allow-root /opt/vendor-suite \
  --output native-isolation-validation.json
```

没有显式 roots 时删去 `--allow-root`；有多个时重复该参数。报告会验证这些 roots 在真实目标机上可见但不可写。

确认报告包含：

```json
"passed": true
```

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

历史 v0.2.0 的新 run 使用 workflow protocol 2；当前 0.4.1 新 run 默认使用 protocol 3，已有 protocol 1/2 run 保留原契约。当前默认 `workflow_mode=auto`：server 在 `assess` 后决定走 full research workflow，还是走 compact verified lane。Compact 只压缩生成侧的 explore/multi-plan/branch 成本，仍然必须经过完整 LaTeX gate、独立 verifier、wrong→repair 和机械 finalizer；如果 compact assembler 发现需要研究性探索，可以主动升级到 full，compact 连续两次 verifier wrong 也会由 server 自动升级到 `explore`。`workflow_mode=full` 可以显式要求完整路线，`workflow_mode=compact` 只是 compact 请求，不会绕过 server 的安全判断。

如果你在做一篇论文或一组互相依赖的定理，可以先创建一个 research project，再把 run 绑定到某个 claim。Project registry 保存在 Re-CTM private trust domain，不在 native workspace 中；`dangerous` Native 权限不会因此获得 project authority。一个已验证 claim 的 revision 是 immutable，后续加强或修订会生成新 revision，并可记录 `depends_on`、`supersedes` 和条件假设。

生命周期上的 `SUPERSEDED` 不等于数学失效：如果一个 VERIFIED/CONDITIONAL revision 后来被新的 OPEN revision 取代，后续 frozen project snapshot 仍保留这个历史已验证 revision，模型可以继续把它作为显式 dependency 使用。Registry promotion 是数学 finalization 的下游第二阶段；即使 promotion 临时失败，已经 `done/correct` 的 proof 和 `proof_verified.tex` 仍然有效，后续 terminal `rethlas_step` 会幂等重试 promotion。

新 run 默认 workflow protocol 3；持久化 protocol 1/2 run 保留原写入契约并可恢复。Protocol 3 添加 typed research events、canonical plan/node IDs、结构化 screening/branch/failure/replan 与有界 advisory context；verifier/finalizer 门禁不变。

Protocol 2/3 assembler 除了完整 LaTeX proof，还提交结构化 `proof_manifest`，其中声明目标 statement、冻结 project snapshot 中实际使用的 dependency revision IDs、material reference IDs、conditional hypotheses 和 computational evidence。只有 LaTeX 通过、server-computed verifier verdict 为 correct、finalizer 完成后，project-linked run 才能机械 promotion 为 `VERIFIED` 或 `CONDITIONAL` revision；模型和 Native tools 都没有 `set_verified` 权限。

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
https://leansearch.net/thm/search
```

可覆盖：

```bash
export RE_CTM_THEOREM_SEARCH_URL=https://leansearch.net/thm/search
export RE_CTM_THEOREM_SEARCH_TIMEOUT_SECONDS=30
```

网页中可以说：

```text
在这个 Rethlas 任务中搜索与当前关键引理有关的外部数学结果，并核对适用条件。
```

`rethlas_retrieve` 的旧调用继续默认为 `theorem_search`。v0.2.0 还支持 typed retrieval：`paper_search`、`paper_lookup` 和 `theorem_context`。Paper provider 固定为受限 HTTPS OpenAlex endpoint；caller 不能传任意 URL 让 server fetch，因此不会把研究检索变成通用 SSRF 入口。所有响应都受 timeout/response-size/content-type 边界约束。

每个 inline 或 retrieved reference 都会得到稳定 `reference_id`；retrieval 还会保存 immutable source snapshot/hash。外部结果一律先是 candidate/external-unverified evidence，不能自动成为证明事实。Protocol-2 proof 必须在 `proof_manifest.reference_ids` 中声明实际依赖的引用；Verifier 对这些引用逐条写 `SOURCE_VERIFIED`、`INDEPENDENTLY_REDERIVED`、`UNRESOLVED` 或 `NOT_MATERIAL` disposition，并同时记录 `evidence_basis` 与 `evidence_locator`。例如 `SOURCE_VERIFIED` 必须说明实际检查的是 run 内保存的 source body snapshot，还是另行检查的 DOI/arXiv/论文位置；LeanSearch/OpenAlex 的 discovery metadata snapshot 本身不能冒充“已核查原论文”。缺失或 unresolved 的 material reference 会由 server 机械加入 verification gap，因此即使 verifier model 忘记报告也不能得到 `correct`。

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

对已经完成但尚未落盘的旧 run，可以直接要求“把这个 run 的最终文件写到默认位置”；当前公开入口是 `rethlas_artifact` 的 `export` 动作，省略路径时会使用该 run 的 `workspace_export_path`。旧 `rethlas_export_final` 名称已退役并会被拒绝；旧 run 的持久化兼容性不恢复旧工具别名。

Protocol-2 run 还可以读取 `proof_manifest` 和 `reference_audit`。Project owner 可以通过同一个 `rethlas_artifact` façade 取得 portable `project_manifest` 或 `project_summary_tex`，并导出到 workspace。Project manifest 只包含 claim/revision/status/hash/dependency/condition/reference-audit 等可发布结构，不包含 owner/OAuth 绑定信息、branch private memory、verifier scratch、capability token 或 steering history；每个已验证 revision 还附带 content-minimized provenance 摘要。`project_summary_tex` 会先经过与 proof 相同的静态外部文件/shell 安全检查；如果 OPEN claim 中出现 `\input`、`\include` 等危险命令，summary `.tex` 会被拒绝，但 JSON project manifest 仍可正常取得。

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

代码清理和重构遵循 [docs/CODE_QUALITY.md](docs/CODE_QUALITY.md) 的功能优先规范。所有优化项目、依赖、详细 TODO、状态和执行回执记录在 `code-optimization-graph.json`；没有具体功能收益、验证标准和回滚方案的“优化”不得进入实施。

单独检查优化图：

```bash
python3 scripts/validate_code_optimization_graph.py
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

在实际部署环境中按当前 RC-001 至 RC-011 验收，并为每一项保留实际候选版本的脱敏证据。旧 MV 检查及原始证据保存在同一文件的历史清单中，已被当前契约清单取代，不代表本次通过。脚本化 loopback OAuth、单元测试、static_only LaTeX 或关闭 Native 执行都不能替代真实客户端、硬隔离、真实编译和数学质量验收。

本机部署验证不要求先推送仓库，也不包含发布、创建公网 tunnel 或访问生产私有状态的授权。只完成当前已获授权的验证；需要真实网页/公网入口或人工数学评审的项目在证据齐备前继续保持 pending。

更完整的服务器部署步骤见：

```text
docs/DEPLOYMENT.md
```


## 新契约迁移与事实图

0.4.1 源码提供 25 个公开工具、默认 protocol 3、schema 8 的创建/提交回执与恢复，
以及通过机械最终化晋升的事实图和有界项目记忆。旧隐藏工具别名已退役。
操作员的 `fact-graph export` / `fact-graph revoke`、备份和回滚边界见
[迁移说明](docs/MTM_MIGRATION.md)。本次只修改和验证源码/临时测试数据，没有迁移运行中的用户数据库。

## 当前目标机发布验收

普通终端验收命令、安全边界、证据路径与剩余门槛见 [TARGET_VALIDATION.md](docs/TARGET_VALIDATION.md)。当前候选尚未达到 release 验收；MTM connector 的嵌套命名空间限制不能通过关闭隔离绕过。
