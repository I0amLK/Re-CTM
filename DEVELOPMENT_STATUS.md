# OPT-027 宿主执行源码交付

日期：2026-11-05。当前候选：**0.5.0rc1 安装候选已构建并通过归档/元数据核对；后续验证由用户执行。此前 dev03（版本字段 0.4.1）的 Mac 源码/宿主工程检查通过记录保留，不转为新安装包验收。**

按 `Re-CTM_TASK_RECORD.md` 实施核心迁移后，用户明确要求“开始测试”。当前测试保留已有工作树修改，只使用一次性 Re-CTM workspace/data/private 状态，没有安装、部署、重启现有服务、读取生产 Re-CTM 私有数据或提交、推送项目。

## 源码改动

- Native：`Settings → build_application → HostExecBackend → NativeRuntime.exec_command → CommandManager → 本机程序`。默认 `disabled`，显式 `host` 才启用；Linux 也不再自动发现或启动 Bubblewrap。旧后端和 helper/attestation 配置报迁移错误。
- 程序解析：使用实际子进程 PATH、单次 `env.PATH` 覆盖与逐命令 cwd，支持绝对程序路径、相对 PATH 项及可执行文件 symlink，保留调用名称。`cmd` 原样交给非 login `/bin/sh -c`；不把 shell 内建、赋值或展开误判成独立可执行文件。没有应用名称、个人工具路径或环境激活特例。
- 命令生命周期：复用已有命令管理器、输入输出、TTY、超时、轮询和终止接口；宿主路径使用独立 `cwd`，不改变服务全局工作目录，不增加代理或常驻服务。
- LaTeX：独立使用宿主 `latexmk` 与现有 `CommandManager`；每次创建新临时目录，保留静态外部文件检查，禁用 RC 加载、shell escape，并设置保守 TeX IO 配置。实测发现环境设置不能阻止绝对路径加载外部 `.cls`，现已在静态检查中拒绝带路径或动态的 class/package 参数，只接受字面的系统搜索名称。`required` 需要成功退出、未超时及本轮新生成的正常 PDF；缺工具、错误、超时或缺产物不能自动降级。
- 配置和报告：增加 `--native-exec-backend host|disabled`，报告基础子进程 PATH 和无 OS 沙箱的真实权限。`check-config` 不再提前创建私有目录、数据库或密钥。打包入口移除 `re-ctm-native-helper`，`attest-native` 返回迁移提示；旧 Linux 固定 launcher 停止激活，保留回滚与历史模板。

## 权限边界

Host 命令及 LaTeX 使用服务账户权限，可能访问同账户私有数据库、密钥及其他文件。环境变量清理、起始 cwd 和直接文件工具检查都不构成进程沙箱。`RE_CTM_NATIVE_EXEC_ALLOW_ROOTS` 只扩展通用程序搜索，不是允许列表或只读挂载。

OAuth、run 所有权、Capability 签名/撤销/作用域、角色与状态规则、Verifier、引用证据与 Finalizer 的授权和判定逻辑未修改；数据库 schema 未修改。`workflow.py` 的唯一改动是人工验收提示文字。直接文件工具的 workspace 约束及 workspace/data/private 不重叠检查保留。Native 命令成功不产生正式数学验证状态。

## 验证与历史

初次 dev02 源码交付没有运行测试。用户随后授权本轮测试，已同步旧后端/launcher/编译夹具、文档契约校验，并补充实际宿主与 required-LaTeX 拒绝路径回归。

`python3 scripts/run_local_checks.py` 已退出 0：573 项测试中 550 项通过、23 项跳过，六个检查项均通过。跳过项为 22 个 Linux/历史隔离后端测试及 1 个 macOS 无法创建无效 UTF-8 文件名的夹具，不将它们算作通过。

实际 Mac 上另以一次性 loopback HTTP 服务完成 17 组工程检查：OAuth DCR/PKCE/MCP，异步请求结束后存活、stdin/TTY、timeout/kill/关闭清理，Git/Python，Sage 绝对路径和单次 PATH，Magma，以及 required LaTeX 到机械 finalizer、Verified fact、幂等成果导出。过程中没有加载 Bubblewrap helper。

首轮 555 项测试的失败、定向测试发现的外部类文件问题，以及临时 HOME 下 Magma 退出 1 的失败均保留。Magma 使用现有 operator HOME 的同一命令退出 0、输出 `5`；这是测试环境差异，没有新增产品专用分支或读取、导出用户配置内容。

验证报告：[OPT-027-macos-host-validation.json](docs/validation/OPT-027-macos-host-validation.json)。HTTP 流程是脚本驱动，数学任务是流程夹具；它们不证明真实浏览器兼容、独立模型推理质量、认知独立性或 95% 方法论等价。没有安装 wheel 或激活 launcher。

`OPT-027` 仍为 `in_progress`，初次源码回执 `REC-2026-11-05-033` 继续作为历史 partial 记录。RC-003/005/006 仅在上述源码/loopback/当前 Mac 范围通过，其余验收继续 pending。此前 checklist 和工程图完整保存在：

- `docs/validation/manual-validation-before-opt027.json`
- `docs/validation/engineering-graph-before-opt027.json`

## 累计交付

用户随后要求“realse 安装包处理一下，后面的验证我自己来”。OPT-028 为此准备独立版本 `0.5.0rc1` 的 wheel、sdist、发行说明和 SHA256 文件，输出至 `dist/release-0.5.0rc1/`。本轮只构建、核对归档内容与版本元数据，不安装或执行安装包，不重跑测试、实机、浏览器或数学验收。说明见 [RELEASE_NOTES.md](RELEASE_NOTES.md)。旧 0.4.1、dev02、dev03 和原始失败证据全部保留。

当前测试后源码输出位置：`dist/opt027-host-dev03/`。此前 dev02 包保留，仍是当时未测试的开发检查点。

- `Re-CTM-host-dev03.zip`：完整源码，含原有工作树修改、本轮实现、修复、测试与验证报告。
- `Re-CTM-host-dev03.patch`：相对 `c6c0424c9faa3eb4287ae404f23be2060acec74e` 的累计差异，包含新增文档和测试。
- `delivery.json`：源码文件清单、内容哈希与交付状态；哈希只标识内容，不代表运行验收。

当前工作区没有历史上传的 `Re-CMT.zip` / dev01 包，无法进行这两个包的逐文件比较；本次以实际工作树为准，未重置现有修改。源码包不含 `.git`、本机 `.env`、运行数据库、密钥、私有状态、安装目录或临时验收输出。dev03 的包版本字段仍为 0.4.1；新发行候选另用 0.5.0rc1，不能套用旧安装的验收结果。
