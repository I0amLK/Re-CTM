# Re-CTM 0.5.0rc1

本包是 macOS 宿主执行迁移的发行候选，供用户安装和后续验证。尚未发布到 GitHub/PyPI，没有安装、部署或修改现有服务。

## 安装文件

- `re_ctm-0.5.0rc1-py3-none-any.whl`：Python 安装包，Python 3.11 及以上。
- `re_ctm-0.5.0rc1.tar.gz`：源码发行包，包含源码、测试、脚本及说明。
- 同目录 `SHA256SUMS`、`release-manifest.json`：文件校验和、来源与验收范围。

系统开发工具、计算软件、LaTeX 及其本机配置不随安装包分发。

## 升级变化

- Native 显式选择 `host` 或 `disabled`，默认 `disabled`。`host` 通过现有单服务和 CommandManager 调用本机程序，不依赖 Bubblewrap。
- 使用真实子进程 PATH、绝对程序路径和逐命令 cwd；没有 Sage/Magma/Conda 专用分支。LaTeX 独立调用宿主 `latexmk`。
- 宿主执行没有 OS 沙箱，可以访问同账户可访问的文件，包括可能的私有数据。工作目录检查、环境变量清理及工具搜索根均不构成进程隔离。
- 旧 `bubblewrap` / `external` 后端、helper/attestation 配置必须显式迁移，不能自动变成宿主模式。`re-ctm-native-helper` console 入口移除；旧固定 Linux launcher 只保留回滚，不用于本候选。
- `required` LaTeX 保留静态检查、禁用 RC/shell escape、超时及本轮新 PDF 要求；编译前拒绝带路径或动态的 class/package 参数，不自动降级。
- OAuth、Capability、角色、状态、Verifier、Finalizer 的授权语义保持不变；仍为 19 Native + 6 Rethlas 工具、protocol 3、schema 8，保留历史 run 协议恢复路径。

## 用户安装步骤

先核对同目录的 `SHA256SUMS`。使用独立环境，不覆盖当前正在使用的安装：

```sh
python3 -m venv .venv-re-ctm-0.5.0rc1
.venv-re-ctm-0.5.0rc1/bin/python -m pip install --no-index --no-deps /path/to/re_ctm-0.5.0rc1-py3-none-any.whl
.venv-re-ctm-0.5.0rc1/bin/re-ctm --version
```

旧 Linux launcher 不适用。后续验证使用独立、互不重叠的 workspace/data/private 根目录，接受宿主权限后显式配置：

```sh
export RE_CTM_WORKSPACE=/path/to/disposable-workspace
export RE_CTM_DATA_ROOT="$HOME/.re-ctm-0.5.0rc1-validation"
export RE_CTM_PRIVATE_ROOT="$RE_CTM_DATA_ROOT/private"
export RE_CTM_NATIVE_EXEC_BACKEND=host
export RE_CTM_LATEX_POLICY=required
.venv-re-ctm-0.5.0rc1/bin/re-ctm tui
```

workspace 必须预先存在且与 data/private 目录互不包含。通过启动环境 PATH、单次 `env.PATH` 或绝对路径选择本机工具；不要把个人路径写入产品默认配置。Magma 的此前测试使用现有 HOME 环境，人工构造的空 HOME 失败记录已保留。

## 验收范围

此前 dev03（版本字段 0.4.1）的源码在本机完成六项检查、573 项测试（550 通过、23 跳过）及 17 组实际宿主工程探测，原始源码验证报告保存在源码包内 `docs/validation/OPT-027-macos-host-validation.json`。这些是历史源码证据，不能当成本候选安装验收。

本轮仅准备 `0.5.0rc1` 版本、构建 wheel/sdist，并核对归档内容、元数据和校验和。没有安装或执行安装包，没有重跑单元测试、实机、浏览器或数学验收。安装、实际客户端与数学质量等后续验证由用户执行；当前候选的 RC 清单保持 pending。
