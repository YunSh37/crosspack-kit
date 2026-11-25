# CrossPack Kit (`crosspack_kit.py`)

一个零第三方依赖的 Python 3.11+ 命令行工具，用于在 macOS / Linux 开发环境下给 **Tauri** 或 **Python PyInstaller** 项目生成 GitHub Actions Windows 打包配置，并静态检查常见的 360 / Windows Defender 误报诱因。

问题背景参考：[V2EX #1259768（Mac 怎么打 Windows 的包）](https://www.v2ex.com/t/1259768)。

---

## 它解决什么问题

在 Mac 或 Linux 上写跨平台桌面程序时，常见做法是推到 GitHub Actions 的 `windows-latest` 上打包。之所以容易一发出去就被 360 或 Defender 拦截，通常是因为默认模板同时踩了几个坑：

- Tauri 只打 NSIS `*-setup.exe`，没有同时产出由系统 `msiexec.exe` 托管的 `.msi` 安装包；
- PyInstaller 用了 `--onefile` 加 UPX 压缩，运行期把 DLL 解压到 `%TEMP%\_MEI*`，节表和释放行为很容易撞启发式查杀；
- 缺少 Windows PE 版本信息（`CompanyName`、`FileDescription`、`ProductVersion`、`LegalCopyright`）和标准 UAC `asInvoker` 清单；
- 打包完直接发压缩包，没有生成 `SHA256SUMS.txt` 校验文件。

`crosspack_kit.py` 只依赖 Python 3.11+ 标准库（`dependencies = []`），包含三个子命令：`init`、`audit`、`checksums`。

---

## 使用方法

可以直接运行单文件脚本 `python3 crosspack_kit.py ...`，也可以在源码目录执行 `pip install -e .` 后调用 `crosspack-kit`。

### 1. 生成 Windows 打包模板（`init`）

**Tauri 项目：**

```bash
python3 crosspack_kit.py init --stack tauri \
  --output /path/to/your-tauri-repo \
  --app-name "MyTauriApp" \
  --publisher "Your Name" \
  --version "0.1.0" \
  --description "Lightweight desktop utility"
```

会在目标目录写入 5 个文件：
- `.github/workflows/build-windows.yml`：在 `windows-latest` 上先校验 `tauri.conf.json` 的 `publisher` / `copyright` / `shortDescription`，再运行 `npx tauri build --bundles msi,nsis`，最后生成 `release/SHA256SUMS.txt` 并在 `v*` tag 时上传 GitHub Release。
- `app.manifest`：标准 Windows UAC `asInvoker` 清单（包含 Windows 7 到 Windows 11 兼容 GUID 与 `PerMonitorV2` DPI 声明）。
- `tauri.windows.bundle.json`：Tauri v2 的 `bundle` 配置参考片段（`targets: ["msi", "nsis"]`、`digestAlgorithm: "sha256"`）。
- `src-tauri-build.rs.example`：`src-tauri/build.rs` 中通过 `tauri_build::WindowsAttributes` 嵌入 `app.manifest` 的示例。
- `SIGNING_AND_AV_CHECKLIST.md`：安装包格式取舍、免费误报申诉入口与开源/云签名路径清单。

**Python + PyInstaller 项目：**

```bash
python3 crosspack_kit.py init --stack python-pyinstaller \
  --output /path/to/your-python-repo \
  --app-name "MyPyApp" \
  --publisher "Your Name" \
  --version "0.1.0" \
  --entry "main.py"
```

会在目标目录写入 6 个文件：
- `.github/workflows/build-windows.yml`：在 `windows-latest` 上执行 `pyinstaller --noconfirm --clean --noupx app.spec`，用 `ISCC.exe` 编译 Inno Setup 安装包并打便携版 `.zip`，最后写入 `release/SHA256SUMS.txt`。
- `windows_version_info.txt`：PyInstaller `VSVersionInfo` 资源文件，包含 `CompanyName`、`FileDescription`、`FileVersion`、`InternalName`、`LegalCopyright`、`OriginalFilename`、`ProductName`、`ProductVersion`。
- `app.manifest`：UAC `asInvoker` 清单。
- `app.spec`：强制 `upx=False` 与 `COLLECT(...)` 目录模式（不使用 `--onefile`）。
- `installer.iss`：Inno Setup 脚本，设置 `PrivilegesRequired=lowest` 与 `asInvoker` 保持一致。
- `SIGNING_AND_AV_CHECKLIST.md`：防误报与签名检查清单。

常用可选参数：`-o / --output`（默认 `.`）、`--app-version`（`--version` 别名）、`--force`（允许覆盖已有文件；默认发现冲突会报错退出）。

---

### 2. 检查现有仓库的误报诱因（`audit`）

```bash
python3 crosspack_kit.py audit /path/to/your-repo
python3 crosspack_kit.py audit /path/to/your-repo --json
python3 crosspack_kit.py audit /path/to/your-repo --stack tauri --allow-medium
```

支持的检查项：
- `UPX_ENABLED` / `PYINSTALLER_MISSING_NOUPX`：检测 `.spec` 中的 `upx=True`、`--upx-dir`、工作流/脚本中直接安装或调用 `upx`，以及未使用 `--noupx` 的 `pyinstaller` 调用（自动跳过注释行，支持 `\` 和 `` ` `` 多行续行）。
- `PYINSTALLER_ONEFILE`：检测 `--onefile` / `-F` 或缺少 `COLLECT(...)` 的 `.spec`。
- `MISSING_UAC_MANIFEST` / `INVALID_UAC_MANIFEST` / `ELEVATED_UAC_MANIFEST`：用 XML 解析检查 `*.manifest`，确认存在且 `requestedExecutionLevel` 为 `asInvoker`。
- `MISSING_VERSION_METADATA` / `INCOMPLETE_VERSION_METADATA` / `MISSING_TAURI_METADATA`：校验 PyInstaller 的 `windows_version_info.txt` 四项核心字段，或 Tauri 的 `publisher`、`copyright`、`shortDescription`。
- `NSIS_WITHOUT_MSI`：提示 Tauri 只配置了 `nsis` 而未包含 `msi`。
- `MISSING_CI_WORKFLOW` / `MISSING_WINDOWS_RUNNER` / `MISSING_SHA256_STEP`：检查 `.github/workflows/` 是否存在 `windows-latest` Runner 及 `SHA256SUMS.txt` 生成步骤。

默认遇到 `HIGH` 或 `MEDIUM` 级别问题时返回退出码 `1`；传入 `--allow-medium` 时仅 `HIGH` 返回 `1`。

---

### 3. 生成与校验 `SHA256SUMS.txt`（`checksums`）

```bash
# 为 release 目录生成 GNU 格式 SHA256SUMS.txt（自动排除 SHA256SUMS.txt 本身）
python3 crosspack_kit.py checksums ./release -o ./release/SHA256SUMS.txt

# 校验校验文件（带路径穿越检查）
python3 crosspack_kit.py checksums --verify -o ./release/SHA256SUMS.txt
```

---

## 适用范围与限制（诚实说明）

- **跨平台构建位置**：`.msi`（WiX）与 Inno Setup `.exe` 仍需由 GitHub Actions `windows-latest` Runner 在云端执行，macOS / Linux 本机不能直接生成 `.msi`。
- **与代码签名的关系**：改用 `.msi` 或 `--onedir --noupx + Inno Setup`、补齐 PE 元数据和 UAC 清单后，360 QVM 启发式误报会明显下降，但**未签名的全新二进制在 Windows 电脑上仍可能触发 SmartScreen 蓝框提示**。公网分发建议配合 [360 软件开放平台误报反馈](https://open.soft.360.cn/report.php)、[Microsoft Security Intelligence](https://www.microsoft.com/wdsi/filesubmission)，开源项目可申请 [SignPath Foundation](https://signpath.org) 免费签名，闭源商业项目可评估 [Azure Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/)。
- **当前测试边界**：自带 `test_crosspack_kit.py` 共 `10` 个 `unittest` 用例，已在离线 Linux Docker（`python3 -m unittest discover -s . -v`）中验证 `init`（AST/XML/JSON 校验及自检 `PASS`）、`audit` 与 `checksums`。生成的 `.yml` 和 `.iss` 模板针对 GitHub Actions Windows 环境编写，未在本地实际连接 Windows Runner 执行编译。

---

## 运行单测

```bash
python3 -m unittest discover -s . -v
```
