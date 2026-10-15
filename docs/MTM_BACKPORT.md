# MTM 兼容功能移植

本批次依据 MTM `b5dbd2577869d2aaf7b0933373df6671d104581c`，更新
Re-CTM `50d08eb89e3ecc46317fd49709fa4ebcda135b5a` 之后的源码。
这是开发中的兼容更新，不是 MTM 的完整移植、已部署版本或新的发布资格。

## 已选功能与接口

### 1. 无损 UTF-8 分页

`read_file` 保留既有参数，新增 `line_byte_offset` 与 `expected_sha256`。
`end_line` 是包含端点的读取范围，`max_lines` 是单页限制，两者可以同时使用。
长行在 UTF-8 字符边界分页，响应提供 `revision`、`next_line_byte_offset` 和
`next_action`。客户端应原样复制 `next_action.arguments`，不要自行递增行号。

例如首个请求为：

```json
{"path":"notes.txt","max_bytes":1024,"max_lines":20}
```

每页内容的 UTF-8 字节数不超过 `max_bytes`。预算连一个完整字符都容纳不下时会
明确报错；文件变动会返回 `READ_FILE_CHANGED`，不会把不同版本的分页拼在一起。
读取限于 workspace 内最大 64 MiB 的普通 UTF-8 文件；这是有界读取，不是任意大小
文件的流式系统，也不承诺跨进程原子快照。

参考：[MTM workspace repair](https://github.com/I0amLK/MTM/blob/b5dbd2577869d2aaf7b0933373df6671d104581c/docs/MTM-016-WORKSPACE-REPAIR.md)。

### 2. workspace 内明确选择 Git 仓库

五个 Git 工具均支持 workspace-relative 的 `repo_path`：

```json
{"repo_path":"packages/example","path":"src/main.py"}
```

该示例可用于 `git_log` 或 `git_blame`；`git_diff`、`git_show` 同样以所选仓库作为
文件过滤根，`git_log` 也支持 `paths` 多路径过滤。没有 `repo_path` 时，`git_status`
继续接受旧 `path` 目录选择方式。
仓库发现不能走到 workspace 上级；Git directory/common-directory 也必须留在
workspace 内。文件过滤使用字面路径，支持已删除文件的历史查询。

状态读取采用 NUL 记录，避免文件名中的换行和 ` -> ` 被拆错；达到结果上限但没有
多余记录时不误报截断。blame 续读保留仓库、revision 和范围。
只读 Git 工具会拒绝配置了 clean/process/smudge helper 的仓库，避免 Git 在普通
读取中绕过 Native 隔离执行程序；不会悄悄禁用 filter 后改变文件规范化语义。
这项拒绝也适用于根仓库，不仅是新增的子仓库路径。
promisor/partial-clone 配置同样被拒绝，工具的 Git 进程禁止 lazy fetch 和所有 remote
transport，避免“读取缺失对象”暗中发起网络连接或启动 remote helper。
这不是对任意恶意 Git 配置、所有并发 metadata race 或非 UTF-8 文件名的完整审计。

参考：同一 MTM workspace repair 文档及 `crates/mtm-runtime/src/workspace_git.rs`。

### 3. 并发首次启动的持久密钥

初始化先完整写入并同步 owner-only 的唯一临时文件，再以不覆盖目标的方式发布，
每个调用都读取实际保存的胜出密钥。已有的空文件、非法密钥、symlink 或非普通文件
均 fail closed，不自动重新生成。临时文件在成功和竞争失败后清理。

这防止特定首次创建竞争导致多个实例持有不同密钥；不允许多个运行时随意共同写入
同一生产数据库，也不修复已经持有不同密钥的进程。既有密钥不会被旋转。

参考：[MTM capability repair R1](https://github.com/I0amLK/MTM/blob/b5dbd2577869d2aaf7b0933373df6671d104581c/docs/MTM-015-CAPABILITY-REPAIR.md)。

### 4. `/mcp` 路径的 OAuth 发现

保留 `/.well-known/oauth-protected-resource`，新增
`/.well-known/oauth-protected-resource/mcp`。新文档的 resource 为完整 `/mcp` URL，
authorization server 仍是 origin。MCP 未授权 challenge 指向新文档。

授权码、token exchange 与 bearer 验证支持精确的 `/mcp` resource/audience，同时
保留历史 origin audience。其他 origin、其他路径及授权时与交换时不一致的 resource
被拒绝；固定 origin 优先与 loopback-only 动态发现限制不变。

参考：同一 MTM capability repair 文档 R7 和 gateway HTTP 回归。

### 5. 简洁 TUI 与可选诊断

`re-ctm tui` 默认显示每次工具开始，保留失败/需修正 submission，省略重复成功行。
`re-ctm tui --verbose` 恢复完成行与 trace 标识。两种模式都不打印工具参数值、
结果正文或 capability。展示层不改写 workflow，也不会自动重放被拒绝的 submission。

参考：MTM `crates/mtm-runtime/src/operator.rs` 和 `submission_events.rs`。

### 6. 保守的 LaTeX 字面文本扫描

静态检查使用有界词法视图，区分支持的 verbatim 字面内容与真正活动的 TeX 控制词。
例如活动的 `\openout1` / `\openin1` 不能因为数字邻接而绕过检查。Literal 屏蔽只用于
文档 wrapper 与括号检查，因此展示 wrapper 或不配对括号的普通附录可以通过；文件、
shell、bibliography 等操作检查始终保留 literal 内容，附录直接展示这些命令仍会拒绝。
这是针对 TeX 重定义绕过采用的保守差异，不宣称完全照搬 MTM 的 literal 接受范围。

原始 LaTeX 继续原样交给既有隔离编译路径；扫描不是 TeX 引擎或通用安全证明。
已知会改变 literal 解释的配置继续被拒绝；即便未知宏重定义了 `\verb`/Verbatim，
直接的禁止操作也不会因为 literal 屏蔽而消失。这不是通用的 TeX 宏展开安全证明。
独立 verifier、repair 和机械 finalizer 门禁保持不变。

参考：[MTM-018 error review](https://github.com/I0amLK/MTM/blob/b5dbd2577869d2aaf7b0933373df6671d104581c/docs/MTM-018-ERROR-REVIEW-20261002.md)
与 `crates/mtm-runtime/src/latex_scan.rs`。

## 兼容边界与另行决策

本批次保持 `re-ctm` / `RE_CTM_*` / `~/.re-ctm` 身份、Python 实现、18 Native +
6 Rethlas = 24 个公开工具、11 个隐藏兼容别名、state schema 2 与 workflow protocol 2。
新增文件分页/Git 可选字段属于已有工具的兼容扩展，Native catalog fingerprint 会据此
明确更新；不把变更后的 schema 描述成与旧 CTM 逐字相同。

以下功能不属于本兼容批次。用户随后明确授权迁移到新契约，正在后续 OPT-018 至
OPT-021 中逐项实现和验证；不能把下面的目标当作已完成结果：

- `apply_changes` 第 25 个公开工具和对应 Native 新契约
- dangerous-only Native，以及删除旧兼容别名
- protocol 3 和 state schema 8 的数学工作流/事实图
- durable creation/step receipts、崩溃后的写入协调与 action recovery
- Rust 改写、安装选择器切换、发布或部署

## 验证与回滚

运行 `python3 scripts/run_local_checks.py`，并保留 `local-validation.json` 的真实结果。
更新前基线在当前云容器运行 142 项测试，其中 8 项因 Bubblewrap attestation 或依赖
它的启动/必需 LaTeX 编译失败；错误包括 NETLINK_ROUTE socket 的 `Operation not
permitted`。不能通过禁用隔离、修改安全测试或跳过失败来宣称目标主机合格。

本批次针对分页、Git、secret publication、OAuth、TUI 和静态 LaTeX 加入独立回归。
最终专项及全量结果以 `local-validation.json` 与 `project-progress.json` 中本批次
记录为准。真实网页、目标主机隔离、真实 LaTeX 编译、外部检索质量及数学方法独立性
仍需重新验收；历史 MTM/Re-CTM 的验收不能自动转用于此源码。

无数据库格式迁移。回滚时只撤回本批次源码、测试与说明，保留已有密钥和 runtime
数据；不要为回滚删除或重新生成 secret。此工作没有提交、推送、安装或发布。
