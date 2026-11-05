# macOS 宿主执行迁移：本次执行状态

日期：2026-11-02。优化记录：OPT-027。

## 上次执行结论（后续进展见文末）

**上次执行未完成；当时所有部分运行时修改均已撤回。**

用户明确指定 macOS 为开发与使用环境，并授权按既定的最小单服务方案实施。
执行尝试遇到了两项独立阻塞：

1. 当前连接器仍使用 `DisabledExecBackend`。实际调用 `python3 --version`
   返回 `NATIVE_ISOLATION_REQUIRED`，因此没有运行测试。
2. 平台安全检查阻止了宿主执行实现补丁的写入。返回信息为：
   `This tool call was blocked by OpenAI's safety checks. Please double check what you are sending.`

第二项阻塞后停止实现，没有换用工具、拆分载荷或使用其他执行路径重试被拒绝的修改。

## 恢复结果

为避免留下无法启动的半成品，已撤回先前成功写入的 `src/re_ctm/native.py`
局部改动，并恢复 `AGENTS.md`、`docs/CODE_QUALITY.md`。
写入工具返回的 SHA256 与改动前基线一致：

| 文件 | 恢复后的 SHA256 |
|---|---|
| `src/re_ctm/native.py` | `9dc7a20008293e142f971b3197978c1000c691cabe806d5ace65c1f2e70a1aa6` |
| `AGENTS.md` | `c9ae5a1254bd99466233d814be4219683596db621bea57631b0495b7992539c6` |
| `docs/CODE_QUALITY.md` | `c7deca92d80be45a0bbf97ecfa8cf0698f8b5f4283f3e3f97e7369a81816bc5d` |

上次执行仅保留此状态说明和 `code-optimization-graph.json` 的 blocked 记录。
源码基线提交为 `c6c0424c9faa3eb4287ae404f23be2060acec74e`。

## 未发生的操作

没有安装或替换正在使用的 Re-CTM，没有重启服务，没有读取或迁移生产私有状态，
没有提交或推送，没有宣称 Git、Python、LaTeX 或工作流实机测试通过。
优化图校验器也因命令执行不可用而尚未运行。

这不是可安装的宿主执行候选版本；现有 Bubblewrap 依赖及执行限制均保持原样。

## 继续执行记录（同日）

再次核实当前连接器仍为 `DisabledExecBackend`，不能执行本机验证命令。
在不删除隔离检查、也不更改 Rethlas 权限的前提下，已完成以下独立准备改动：

- `src/re_ctm/processes.py`：为 `CommandManager.start`、`spawn_process`、
  `_spawn_process_owned` 增加可选 `cwd` 参数，最终向子进程 `Popen` 传递。
  未提供 `cwd` 时保持原有进程启动行为；不调用全局 `os.chdir()`。
- `tests/test_command_v11.py`：新增回归测试，检查带空格工作目录、
  每个命令独立工作目录以及 Re-CTM 服务的工作目录不发生变化。

上述代码已写入工作树，**未执行测试**。该准备改动没有开启宿主命令执行、
没有修改 `native.py` 隔离门禁，也没有触及 Rethlas 的授权或私有数据。
此前宿主执行补丁被平台安全检查拒绝的事实依旧成立；不尝试绕过该拒绝。
完整迁移继续标记为 blocked。该记录不代表 macOS 宿主执行已实现或安全验收已通过。

## CTM 连接器 macOS 本地检查（2026-11-02）

用户提供了 macOS 上的失败报告；本次通过单独的 Coding Tools MCP 连接器完成现有代码的测试兼容性修复，并实际在 Mac 上执行 `python3 scripts/run_local_checks.py`。
修复集中于测试夹具：macOS 的 `/var` 与 `/private/var` 路径别名使用 `Path.resolve()` 规范化；保留对真实 symlink 的拒绝测试。
Git 的 `includeIf.gitdir` 测试因此能够匹配规范化路径，仍必须拒绝外部 filter。
文件系统拒绝创建无效 UTF-8 文件名且报 `EILSEQ` 时，只在 Darwin 跳过无法建立的测试夹具，并非降低 Git 生产代码的安全检查。

实际检查结果：`run_local_checks.py` 退出码 0，六项检查均通过；`unittest` 执行 555 项，`OK (skipped=27)`。
这属于当前源码的确定性本地回归，**不是 host backend、真实 LaTeX 或目标发布验收**。
当前仍未移除 Bubblewrap，没有恢复 `exec_command` 的 host 路径，也未安装、重启或修改生产私有数据。

## macOS Native 工具链验收补充：Miniconda 环境（2026-11-02）

本节属于 OPT-027 的验收方案与已取得的主机证据；它**不代表 Re-CTM 的 host backend 已实现或验收通过**。
通过 Mac 上的 Coding Tools MCP（CTM）确认：

| 项目 | 已确认事实 |
|---|---|
| Conda 可执行文件 | `/Users/lk/miniconda3/bin/conda` |
| 环境名称 | `sage` |
| 环境前缀 | `/Users/lk/miniconda3/envs/sage` |
| SageMath 版本 | Conda 包 `sage=10.9`、`sagelib=10.9` |
| Sage 可执行文件 | `/Users/lk/miniconda3/envs/sage/bin/sage` |
| 绝对路径执行 | `sage -c 'print(2+3)'`（使用上述可执行文件的完整路径），stdout `5`，exit code `0` |
| 临时 PATH 执行 | `PATH="/Users/lk/miniconda3/envs/sage/bin:$PATH" sage -c 'print(2+3)'`，stdout `5`，exit code `0` |

上述路径是**本机验收证据**，不是运行时默认值。不得把 SageMath、环境名 `sage`、
或 `/Users/lk/miniconda3/envs/sage` 写死到 Native 的程序发现、允许列表、默认 PATH、启动脚本或平台分支。

### Re-CTM 迁移完成后的待验收项目

1. 用子进程的有效 PATH（服务启动 PATH + 本次 `env.PATH` 覆盖）解析程序；
   支持用户提供的绝对路径与任意 Conda、venv 环境中的可执行文件，不预设任何应用名称。
   找不到的程序应如实报错，不得自动猜测或激活预设环境。
2. 从 `conda info --envs` 或 `conda run -n sage` 发现本机测试环境及其可执行文件；
   将发现到的 `bin` 临时加入**一次** `exec_command` 的 `env.PATH` 后执行
   `argv=["sage","-c","print(2+3)"]`，要求 stdout `5`、exit code `0`。
   再用运行时发现的绝对 Sage 可执行文件路径执行同一计算，要求结果相同。
   环境名 `sage` 只是可替换的**测试夹具**，不可成为产品的特殊逻辑。
3. 在一次性 Workspace 中，用同一通用执行器验证 Git、Python、其他已有 CLI，
   检查逐命令 `cwd`、stdout/stderr、timeout、kill、进程结束状态和服务全局 cwd 不变。
4. `check_exec_environment` 必须反映实际后端与有效 PATH，不泄漏凭据；
   在 `host` 模式必须如实声明没有 OS 沙箱，不能再宣称 Native 无法读写同账户的 Rethlas 私有状态。
5. 运行 Rethlas 的 OAuth、Capability、角色、状态、Verifier、Finalizer 回归及
   `required` LaTeX 真实编译门禁。以上新增的 CLI 测试必须通过**改造后的 Re-CTM**完成，
   不能用 CTM 已成功执行的结果代替 Re-CTM 验收。

完成条件：不依赖 Bubblewrap、不针对 SageMath 写特殊发现逻辑时，Re-CTM 能通过
绝对路径与有效 PATH 执行已安装的通用工具，且 Rethlas API 授权和机械最终化规则保持不变。
**当前 OPT-027 仍为 blocked；本次只补充验收文档，不变更运行时代码或生产环境。**

## 核心源码继续实施（2026-11-05）

上述 blocked 和测试结果均为历史记录。当前按 `Re-CTM_TASK_RECORD.md` 已写入显式 host/disabled 配置、应用初始化、Native exec_command 至现有 CommandManager 的宿主调用链，以及独立的宿主 LaTeX 编译路径。Native 与 LaTeX 的当前配置路径均不再调用或验收 Bubblewrap。旧隔离适配器与专项测试保留供历史回归，不再属于当前应用的后端选项。

程序解析使用真实子进程 PATH、绝对程序路径和逐命令 cwd，保留 shell 文本与 argv 的区别，没有 Sage/Conda/个人路径特例。环境报告明确宿主没有 OS 沙箱，私有文件可能被同账户进程访问。Rethlas API 授权与机械判定逻辑保持原样。

状态为 **已修改、未运行、未验证**。按用户要求，本阶段未运行测试、校验器、编译或工具试跑；旧隔离测试夹具待统一测试阶段同步。本地生产服务、安装和私有数据未动。OPT-027 改为 in_progress，回执 REC-2026-11-05-033 为 partial；历史通过记录不转移至本候选。

交付说明：`DEVELOPMENT_STATUS.md`；累计源码与补丁：`dist/opt027-host-dev02/`。原上传 ZIP/dev01 不在本工作区，本次基于实际源码和已有工作树修改保留累计交付。

## 用户随后授权测试后的结果（2026-11-05）

用户明确要求“开始测试”后，本机已完成源码与实际宿主工程测试。完整本地检查退出 0：573 项测试中 550 项通过、23 项平台/历史后端测试跳过，六个检查项通过。实际 Mac 另有 17 组源码 OAuth/MCP/Native/工具/required-LaTeX/最终化与关闭清理检查通过，没有加载 Bubblewrap helper。

本轮同步了旧夹具及文档校验契约，并修复实际编译复现的外部绝对 `.cls` 加载问题：编译前拒绝非字面或含路径的 class/package 参数。首轮失败、修复前外部类文件测试失败与临时 HOME 的 Magma 失败保留；Magma 使用现有 operator HOME 的同一命令退出 0、输出 `5`，未增加产品特殊分支。

报告见 `docs/validation/OPT-027-macos-host-validation.json`，原始日志在 `.release-validation/opt027-20261104T195921Z/`，测试后源码包与累计补丁在 `dist/opt027-host-dev03/`。当前安装、生产 Re-CTM 私有数据和正在运行的服务均未操作；没有项目提交或推送。

这只构成当前 Mac 源码/宿主工程证据。安装包、真实浏览器、独立模型数学质量、认知独立性与 95% 方法论等价未验收；OPT-027 保持 in_progress，历史源码交付记录与旧 Linux 验收记录不改写。

