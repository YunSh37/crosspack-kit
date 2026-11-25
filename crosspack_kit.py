#!/usr/bin/env python3
"""CrossPack Kit: zero-dependency CLI for cross-building Windows installers via CI and preventing AV false positives.

Solves cross-platform Windows packaging from macOS/Linux via GitHub Actions while
eliminating common 360 Total Security / Windows Defender false-positive triggers:
- Eliminates UPX packing and PyInstaller `--onefile` temp extraction heuristics
- Embeds complete PE VersionInfo metadata and UAC `asInvoker` manifests
- Prioritizes WiX `.msi` (Tauri) and `--onedir --noupx` + Inno Setup (PyInstaller)
- Audits existing repositories for AV false-positive triggers
- Generates reproducible `SHA256SUMS.txt` checksums for release artifacts
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence
from xml.sax.saxutils import escape as xml_escape

__version__ = "0.1.0"

SUPPORTED_STACKS: tuple[str, ...] = ("tauri", "python-pyinstaller")

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "target",
        "dist",
        "build",
        ".tmp",
    }
)

REQUIRED_VERSION_FIELDS: tuple[str, ...] = (
    "CompanyName",
    "FileDescription",
    "ProductVersion",
    "LegalCopyright",
)


@dataclass(frozen=True)
class AuditFinding:
    """Represents a single audit finding with an actionable remediation."""

    rule_id: str
    severity: str  # "HIGH" | "MEDIUM" | "INFO"
    message: str
    fix: str
    file_path: str = ""
    line_number: int | None = None


@dataclass
class AuditReport:
    """Aggregated audit report for a target project directory."""

    target: str
    detected_stack: str
    status: str  # "PASS" | "FAIL"
    findings: list[AuditFinding] = field(default_factory=list)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "INFO")

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "detected_stack": self.detected_stack,
            "status": self.status,
            "summary": {
                "high": self.high_count,
                "medium": self.medium_count,
                "info": self.info_count,
            },
            "findings": [asdict(item) for item in self.findings],
        }


def parse_semver_tuple(version: str) -> tuple[int, int, int, int]:
    """Validate semantic version and convert it into a 4-part Windows version tuple."""
    cleaned = version.strip().lstrip("vV")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", cleaned)
    if not match:
        raise ValueError(
            f"Invalid version '{version}'. Expected semantic version like '0.1.0' or '1.2.3.0'."
        )
    parts = [int(group) for group in match.groups(default="0")]
    if any(p < 0 or p > 65535 for p in parts):
        raise ValueError(
            f"Version components in '{version}' must be between 0 and 65535 for Windows PE resources."
        )
    return parts[0], parts[1], parts[2], parts[3]


def sanitize_slug(app_name: str) -> str:
    """Convert an application display name into an identifier-safe slug."""
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", app_name.strip().lower()).strip("-_")
    return slug or "crosspack-app"


def render_app_manifest(app_name: str, slug: str, version: str, description: str) -> str:
    """Render a standard Windows UAC asInvoker XML application manifest."""
    v1, v2, v3, v4 = parse_semver_tuple(version)
    win_ver = f"{v1}.{v2}.{v3}.{v4}"
    safe_slug = xml_escape(slug)
    safe_desc = xml_escape(description or app_name)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
        f'  <assemblyIdentity version="{win_ver}" processorArchitecture="*" name="{safe_slug}" type="win32"/>\n'
        f"  <description>{safe_desc}</description>\n"
        '  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\n'
        "    <security>\n"
        "      <requestedPrivileges>\n"
        '        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>\n'
        "      </requestedPrivileges>\n"
        "    </security>\n"
        "  </trustInfo>\n"
        '  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">\n'
        "    <application>\n"
        "      <!-- Windows 10 and Windows 11 -->\n"
        '      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>\n'
        "      <!-- Windows 8.1 -->\n"
        '      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>\n'
        "      <!-- Windows 8 -->\n"
        '      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>\n'
        "      <!-- Windows 7 -->\n"
        '      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>\n'
        "    </application>\n"
        "  </compatibility>\n"
        '  <application xmlns="urn:schemas-microsoft-com:asm.v3">\n'
        "    <windowsSettings>\n"
        '      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>\n'
        "    </windowsSettings>\n"
        "  </application>\n"
        "</assembly>\n"
    )


def render_windows_version_info(
    app_name: str,
    slug: str,
    publisher: str,
    version: str,
    description: str,
    copyright_text: str,
) -> str:
    """Render a PyInstaller VSVersionInfo resource file with complete PE metadata."""
    v1, v2, v3, v4 = parse_semver_tuple(version)
    win_ver = f"{v1}.{v2}.{v3}.{v4}"
    clean_ver = version.strip().lstrip("vV")
    return (
        "# UTF-8\n"
        "# PyInstaller Windows PE VersionInfo metadata\n"
        "# Missing CompanyName / FileDescription / ProductVersion / LegalCopyright\n"
        "# is a leading cause of 360 and Defender heuristic false positives.\n"
        "VSVersionInfo(\n"
        "  ffi=FixedFileInfo(\n"
        f"    filevers=({v1}, {v2}, {v3}, {v4}),\n"
        f"    prodvers=({v1}, {v2}, {v3}, {v4}),\n"
        "    mask=0x3f,\n"
        "    flags=0x0,\n"
        "    OS=0x40004,\n"
        "    fileType=0x1,\n"
        "    subtype=0x0,\n"
        "    date=(0, 0)\n"
        "  ),\n"
        "  kids=[\n"
        "    StringFileInfo([\n"
        "      StringTable(\n"
        "        '040904B0',\n"
        "        [\n"
        f"          StringStruct('CompanyName', {publisher!r}),\n"
        f"          StringStruct('FileDescription', {description!r}),\n"
        f"          StringStruct('FileVersion', {win_ver!r}),\n"
        f"          StringStruct('InternalName', {slug!r}),\n"
        f"          StringStruct('LegalCopyright', {copyright_text!r}),\n"
        f"          StringStruct('OriginalFilename', {f'{slug}.exe'!r}),\n"
        f"          StringStruct('ProductName', {app_name!r}),\n"
        f"          StringStruct('ProductVersion', {clean_ver!r}),\n"
        "        ]\n"
        "      )\n"
        "    ]),\n"
        "    VarFileInfo([VarStruct('Translation', [1033, 1200])])\n"
        "  ]\n"
        ")\n"
    )


def render_pyinstaller_spec(slug: str, entry: str) -> str:
    """Render a PyInstaller .spec file enforcing onedir + noupx + PE metadata + manifest."""
    return (
        "# -*- mode: python ; coding: utf-8 -*-\n"
        "# CrossPack Kit PyInstaller Spec (AV-friendly: onedir + noupx + metadata + UAC manifest)\n\n"
        "a = Analysis(\n"
        f"    [{entry!r}],\n"
        "    pathex=[],\n"
        "    binaries=[],\n"
        "    datas=[],\n"
        "    hiddenimports=[],\n"
        "    hookspath=[],\n"
        "    hooksconfig={},\n"
        "    runtime_hooks=[],\n"
        "    excludes=[],\n"
        "    noarchive=False,\n"
        "    optimize=0,\n"
        ")\n"
        "pyz = PYZ(a.pure)\n\n"
        "exe = EXE(\n"
        "    pyz,\n"
        "    a.scripts,\n"
        "    [],\n"
        "    exclude_binaries=True,\n"
        f"    name={slug!r},\n"
        "    debug=False,\n"
        "    bootloader_ignore_signals=False,\n"
        "    strip=False,\n"
        "    upx=False,\n"
        "    console=False,\n"
        "    disable_windowed_traceback=False,\n"
        "    argv_emulation=False,\n"
        "    target_arch=None,\n"
        "    codesign_identity=None,\n"
        "    entitlements_file=None,\n"
        "    version='windows_version_info.txt',\n"
        "    manifest='app.manifest',\n"
        ")\n"
        "coll = COLLECT(\n"
        "    exe,\n"
        "    a.binaries,\n"
        "    a.datas,\n"
        "    strip=False,\n"
        "    upx=False,\n"
        "    upx_exclude=[],\n"
        f"    name={slug!r},\n"
        ")\n"
    )


def render_inno_setup_iss(
    app_name: str,
    slug: str,
    publisher: str,
    version: str,
    description: str,
    copyright_text: str,
) -> str:
    """Render an Inno Setup script wrapping the PyInstaller --onedir output cleanly."""
    v1, v2, v3, v4 = parse_semver_tuple(version)
    win_ver = f"{v1}.{v2}.{v3}.{v4}"
    clean_ver = version.strip().lstrip("vV")
    app_guid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"crosspack.{slug}")).upper()
    return (
        f"; CrossPack Kit Inno Setup Script for {app_name}\n"
        f'#define MyAppName "{app_name}"\n'
        f'#define MyAppSlug "{slug}"\n'
        f'#define MyAppVersion "{clean_ver}"\n'
        f'#define MyAppPublisher "{publisher}"\n'
        f'#define MyAppExeName "{slug}.exe"\n\n'
        "[Setup]\n"
        f"AppId={{{{{app_guid}}}}}\n"
        "AppName={#MyAppName}\n"
        "AppVersion={#MyAppVersion}\n"
        "AppPublisher={#MyAppPublisher}\n"
        f"VersionInfoCompany={publisher}\n"
        f"VersionInfoDescription={description}\n"
        f"VersionInfoVersion={win_ver}\n"
        f"VersionInfoCopyright={copyright_text}\n"
        "DefaultDirName={autopf}\\{#MyAppName}\n"
        "DefaultGroupName={#MyAppName}\n"
        "PrivilegesRequired=lowest\n"
        "PrivilegesRequiredOverridesAllowed=dialog\n"
        "OutputDir=release\n"
        f"OutputBaseFilename={slug}-{clean_ver}-windows-x64-setup\n"
        "Compression=lzma2/normal\n"
        "SolidCompression=yes\n"
        "WizardStyle=modern\n"
        "ArchitecturesAllowed=x64compatible\n"
        "ArchitecturesInstallIn64BitMode=x64compatible\n\n"
        "[Languages]\n"
        'Name: "english"; MessagesFile: "compiler:Default.isl"\n\n'
        "[Tasks]\n"
        'Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked\n\n'
        "[Files]\n"
        f'Source: "dist\\{slug}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs\n\n'
        "[Icons]\n"
        'Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"\n'
        'Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon\n\n'
        "[Run]\n"
        'Filename: "{app}\\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, \'&\', \'&&\')}}"; Flags: nowait postinstall skipifsilent\n'
    )


def render_pyinstaller_workflow(slug: str, version: str) -> str:
    """Render a GitHub Actions windows-latest workflow for PyInstaller onedir+InnoSetup."""
    return f"""name: Build Windows Installer (PyInstaller)

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  build-windows:
    runs-on: windows-latest
    steps:
      - name: Checkout source
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install dependencies and PyInstaller
        shell: pwsh
        run: |
          python -m pip install --upgrade pip
          if (Test-Path requirements.txt) {{ pip install -r requirements.txt }}
          pip install pyinstaller

      - name: Build onedir bundle without UPX
        shell: pwsh
        run: |
          pyinstaller --noconfirm --clean --noupx app.spec

      - name: Build Inno Setup installer
        shell: pwsh
        run: |
          $iscc = "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe"
          if (-not (Test-Path $iscc)) {{
            choco install innosetup -y --no-progress
          }}
          New-Item -ItemType Directory -Force -Path release | Out-Null
          & $iscc installer.iss
          Compress-Archive -Path "dist\\{slug}\\*" -DestinationPath "release\\{slug}-portable-windows-x64.zip" -Force

      # Optional: Code signing (SignPath OSS / Azure Artifact Signing / signtool)
      # - name: Sign Windows artifacts
      #   if: env.SIGN_ENABLED == 'true'
      #   shell: pwsh
      #   run: |
      #     Write-Host "Configure SignPath or Azure Artifact Signing here"

      - name: Generate SHA256SUMS.txt
        shell: pwsh
        run: |
          python -c "import hashlib, pathlib; rel = pathlib.Path('release'); files = sorted(p for p in rel.iterdir() if p.is_file() and p.name != 'SHA256SUMS.txt'); lines = [f'{{hashlib.sha256(p.read_bytes()).hexdigest()}}  {{p.name}}' for p in files]; (rel / 'SHA256SUMS.txt').write_text('\\n'.join(lines) + '\\n', encoding='utf-8')"
          Get-Content release\\SHA256SUMS.txt

      - name: Upload Windows build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: windows-release-{slug}
          path: release/*

      - name: Publish GitHub Release on tag
        if: startsWith(github.ref, 'refs/tags/v')
        uses: softprops/action-gh-release@v2
        with:
          files: |
            release/*.exe
            release/*.zip
            release/SHA256SUMS.txt
"""


def render_tauri_workflow(slug: str) -> str:
    """Render a GitHub Actions windows-latest workflow for Tauri MSI/NSIS builds."""
    return f"""name: Build Windows Installer (Tauri)

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  build-windows:
    runs-on: windows-latest
    steps:
      - name: Checkout source
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable

      - name: Rust cache
        uses: swatinem/rust-cache@v2
        with:
          workspaces: 'src-tauri -> target'

      - name: Verify Windows publisher metadata before building
        shell: pwsh
        run: |
          python -c "import json, pathlib, sys; candidates = [pathlib.Path('src-tauri/tauri.conf.json'), pathlib.Path('tauri.conf.json'), pathlib.Path('tauri.windows.bundle.json')]; cfg_path = next((p for p in candidates if p.exists()), None); assert cfg_path, 'Missing Tauri config'; data = json.loads(cfg_path.read_text(encoding='utf-8')); bundle = data.get('bundle') or data.get('tauri', {{}}).get('bundle', {{}}); missing = [k for k in ('publisher', 'copyright', 'shortDescription') if not str(bundle.get(k, '')).strip()]; sys.exit('Missing Tauri bundle metadata: ' + ', '.join(missing)) if missing else print('Verified Tauri bundle metadata in', cfg_path)"

      - name: Install frontend dependencies
        shell: pwsh
        run: |
          if (Test-Path pnpm-lock.yaml) {{
            corepack enable
            pnpm install --frozen-lockfile
          }} elseif (Test-Path yarn.lock) {{
            yarn install --frozen-lockfile
          }} else {{
            npm ci
          }}

      - name: Build Tauri MSI (primary) and NSIS installers
        shell: pwsh
        run: |
          # Building WiX .msi alongside .exe gives end users an msiexec-managed package
          # with significantly fewer 360/QVM heuristic false positives than bare setup.exe.
          npx tauri build --bundles msi,nsis

      - name: Collect release installers and generate SHA256SUMS.txt
        shell: pwsh
        run: |
          New-Item -ItemType Directory -Force -Path release | Out-Null
          Get-ChildItem -Path "src-tauri\\target\\release\\bundle" -Recurse -Include *.msi,*.exe | Copy-Item -Destination release\\ -Force
          python -c "import hashlib, pathlib; rel = pathlib.Path('release'); files = sorted(p for p in rel.iterdir() if p.is_file() and p.name != 'SHA256SUMS.txt'); lines = [f'{{hashlib.sha256(p.read_bytes()).hexdigest()}}  {{p.name}}' for p in files]; (rel / 'SHA256SUMS.txt').write_text('\\n'.join(lines) + '\\n', encoding='utf-8')"
          Get-Content release\\SHA256SUMS.txt

      - name: Upload Windows installers
        uses: actions/upload-artifact@v4
        with:
          name: windows-release-{slug}
          path: release/*

      - name: Publish GitHub Release on tag
        if: startsWith(github.ref, 'refs/tags/v')
        uses: softprops/action-gh-release@v2
        with:
          files: |
            release/*.msi
            release/*.exe
            release/SHA256SUMS.txt
"""


def render_tauri_bundle_snippet(
    app_name: str,
    publisher: str,
    version: str,
    description: str,
    copyright_text: str,
) -> str:
    """Render a Tauri v2 bundle configuration snippet with complete publisher metadata."""
    clean_ver = version.strip().lstrip("vV")
    payload = {
        "productName": app_name,
        "version": clean_ver,
        "bundle": {
            "active": True,
            "targets": ["msi", "nsis"],
            "publisher": publisher,
            "copyright": copyright_text,
            "shortDescription": description,
            "longDescription": f"{app_name}: {description}",
            "windows": {
                "certificateThumbprint": None,
                "digestAlgorithm": "sha256",
                "timestampUrl": "http://timestamp.digicert.com",
                "wix": {
                    "language": ["en-US", "zh-CN"],
                },
                "nsis": {
                    "installMode": "currentUser",
                    "compression": "lzma",
                },
            },
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_tauri_build_rs_example() -> str:
    """Render example src-tauri/build.rs showing how to embed app.manifest in Tauri."""
    return (
        "// Example src-tauri/build.rs snippet for embedding app.manifest in Tauri v2\n"
        "// Place app.manifest in src-tauri/app.manifest (or adjust include_str! path).\n"
        "fn main() {\n"
        "    let windows = tauri_build::WindowsAttributes::new()\n"
        '        .app_manifest(include_str!("app.manifest"));\n'
        "    let attrs = tauri_build::Attributes::new().windows_attributes(windows);\n"
        "    tauri_build::try_build(attrs).expect(\"failed to run tauri-build\");\n"
        "}\n"
    )


def render_signing_and_av_checklist(stack: str, app_name: str) -> str:
    """Render actionable AV false-positive elimination and signing checklist."""
    return f"""# Windows 打包防误报与代码签名检查清单 ({app_name} / {stack})

本清单用于解决 **macOS / Linux 开发者通过 GitHub Actions 跨平台打包 Windows 安装包** 时，被 360 安全卫士、Windows Defender / SmartScreen 误报为木马的问题。

---

## 1. 为什么 GitHub Actions 打出的包容易被 360 误报？

1. **无合法数字签名 + 自解压包装器启发式命中**：
   - Tauri 默认产出的 `*-setup.exe` 使用 **NSIS** 自解压安装器；PyInstaller 默认 `--onefile` 会在运行时把 DLL/PYD 解压到 `%TEMP%\\_MEIxxxxxx`。
   - 360 QVM 启发式引擎对“无 Authenticode 数字签名 + 无历史装机量信誉 + 自解压释放可执行文件”的组合极为敏感，极易触发木马误报。
2. **PE 版本元数据与 UAC Manifest 缺失**：
   - 缺少 `CompanyName`、`FileDescription`、`ProductVersion`、`LegalCopyright` 和标准 `asInvoker` 清单的可执行文件，在安全引擎眼中属于“无来源未知程序”。
3. **UPX 加壳破坏节区特征**：
   - 对 PyInstaller 或 Rust 二进制使用 UPX 压缩会修改 PE 节表（`UPX0` / `UPX1`）并引入运行时解壳行为，几乎必然触发杀软告警。
4. **微信 / QQ 直传 zip 叠加 MOTW（Mark of the Web）**：
   - 聊天工具发送的无签名 `.zip/.exe` 没有公开 HTTPS 下载来源与校验信息，容易直接被拦截。

---

## 2. 构建阶段改动（无需花钱）

### A. 不用 UPX 和 PyInstaller `--onefile`
- **PyInstaller 项目**：用 `--onedir --noupx`（或在 `.spec` 中明确写 `upx=False`），再配合 **Inno Setup (`installer.iss`)** 或 WiX 打安装包。
- **Tauri 项目**：在 `windows-latest` 上跑 `tauri build --bundles msi,nsis`，优先发 `.msi`。`.msi` 由系统原生 `msiexec.exe` 安装，结构透明，比未签名的 NSIS `setup.exe` 更少触发 360 误报。

### B. 补齐 PE 版本信息与 UAC 清单
- **PyInstaller**：通过 `--version-file windows_version_info.txt` 嵌入 `CompanyName`、`FileDescription`、`ProductVersion`、`LegalCopyright`，并通过 `--manifest app.manifest` 声明 `level="asInvoker"`。
- **Tauri**：在 `tauri.conf.json` 的 `bundle` 中填全 `publisher`、`copyright`、`shortDescription`、`longDescription`，并在 `src-tauri/build.rs` 中嵌入 `app.manifest`（不需要管理员权限就别写 `requireAdministrator`）。

### C. 发布方式与哈希校验
- CI 最后为安装包生成 `SHA256SUMS.txt`（`python3 crosspack_kit.py checksums release/`）。
- 通过 **GitHub Releases**（HTTPS 下载）附带 `SHA256SUMS.txt` 分发，尽量别直接微信发裸 `.exe` 压缩包。

---

## 3. 免费白名单申诉与开源免费签名渠道

| 场景 | 渠道 | 费用 | 作用说明 |
| :--- | :--- | :--- | :--- |
| 360 误报解除（快速反馈） | [360 软件开放平台误报反馈](https://open.soft.360.cn/report.php) / 邮箱 `opensoft@360.cn` | **免费** | 提交未加密安装包 + 误报截图 + 用途说明，官方通常 1~2 个工作日审核入库 |
| 360 开发者认证 | [360 软件开放平台](https://open.soft.360.cn/) | **免费** | 注册开发者并提交版本安全认证，长期减少新版误报 |
| Windows Defender 误报申诉 | [Microsoft Security Intelligence](https://www.microsoft.com/wdsi/filesubmission) | **免费** | 选择 `Software developer` 提交误报样本（若本地被拦截，可用密码 `infected` 打包 zip 上传） |
| 开源项目自动化签名 | [SignPath Foundation](https://signpath.org) | **免费（需符合 OSI 开源条件）** | 为合格开源项目提供托管 HSM 签名与 GitHub Actions 集成，消除 SmartScreen 警告 |

---

## 4. 自签名证书 vs 商业云端代码签名说明

- **自签名证书（`New-SelfSignedCertificate` + `signtool`）的局限**：
  - 自签名证书**无法**消除陌生用户电脑上的 Windows SmartScreen 或 360 警告！仅适合“自己/亲友固定几台电脑”且事先手动把 `.cer` 公钥导入到目标电脑 `受信任的根证书颁发机构` 的内网场景。
- **低成本商业云签名（闭源/独立开发者推荐）**：
  - **Azure Artifact Signing**（原名 Microsoft Trusted Signing）：[官方文档](https://learn.microsoft.com/en-us/azure/artifact-signing/)。基础套餐约 $9.99/月（需付费 Azure 订阅与身份审核，不支持试用/免费额度），无需购买实体 USB Key 即可在 GitHub Actions 中自动化签名并加速建立 SmartScreen 信誉。
  - **传统 CA（DigiCert / Sectigo / SSL.com 等）**：适合企业级发行，需遵循新规使用硬件 Token 或云 HSM 托管签名，切勿将明文私钥或 PFX 密码硬编码进仓库。
"""


def init_bundle(
    stack: str,
    output_dir: Path,
    app_name: str = "MyCrossApp",
    publisher: str = "Independent Developer",
    version: str = "0.1.0",
    description: str = "Cross-platform desktop application",
    entry: str = "main.py",
    force: bool = False,
) -> list[Path]:
    """Generate a complete Windows cross-packaging bundle for the specified stack."""
    if stack not in SUPPORTED_STACKS:
        raise ValueError(f"Unsupported stack '{stack}'. Expected one of: {', '.join(SUPPORTED_STACKS)}")

    parse_semver_tuple(version)
    slug = sanitize_slug(app_name)
    copyright_text = f"Copyright (c) 2026 {publisher}"

    files: dict[str, str] = {
        "app.manifest": render_app_manifest(app_name, slug, version, description),
        "SIGNING_AND_AV_CHECKLIST.md": render_signing_and_av_checklist(stack, app_name),
    }

    if stack == "python-pyinstaller":
        files[".github/workflows/build-windows.yml"] = render_pyinstaller_workflow(slug, version)
        files["windows_version_info.txt"] = render_windows_version_info(
            app_name=app_name,
            slug=slug,
            publisher=publisher,
            version=version,
            description=description,
            copyright_text=copyright_text,
        )
        files["app.spec"] = render_pyinstaller_spec(slug=slug, entry=entry)
        files["installer.iss"] = render_inno_setup_iss(
            app_name=app_name,
            slug=slug,
            publisher=publisher,
            version=version,
            description=description,
            copyright_text=copyright_text,
        )
    else:
        files[".github/workflows/build-windows.yml"] = render_tauri_workflow(slug)
        files["tauri.windows.bundle.json"] = render_tauri_bundle_snippet(
            app_name=app_name,
            publisher=publisher,
            version=version,
            description=description,
            copyright_text=copyright_text,
        )
        files["src-tauri-build.rs.example"] = render_tauri_build_rs_example()

    target_paths = {rel: output_dir / rel for rel in files}
    if not force:
        existing = [str(path) for path in target_paths.values() if path.exists()]
        if existing:
            raise FileExistsError(
                "Target files already exist (re-run with --force to overwrite): "
                + ", ".join(existing)
            )

    written: list[Path] = []
    for rel, content in files.items():
        dest = target_paths[rel]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="\n")
        written.append(dest)
    return written


def _iter_project_files(root: Path) -> Iterable[Path]:
    """Yield non-ignored regular files under root."""
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(current_root)
        for name in sorted(filenames):
            yield base / name


def _strip_hash_comments(line: str) -> str:
    """Strip unquoted `#` comments while preserving quoted strings."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and (in_single or in_double):
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:idx]
    return line


def _join_continued_lines(text: str) -> list[tuple[int, str]]:
    """Join shell/PowerShell line continuations (`\\` or `` ` ``) and track start line."""
    joined: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 1
    for lineno, raw in enumerate(text.splitlines(), start=1):
        code = _strip_hash_comments(raw).rstrip()
        if not buffer:
            start_line = lineno
        if code.endswith("\\") or code.endswith("`"):
            buffer.append(code[:-1].rstrip())
            continue
        buffer.append(code)
        combined = " ".join(part for part in buffer if part).strip()
        if combined:
            joined.append((start_line, combined))
        buffer.clear()
    if buffer:
        combined = " ".join(part for part in buffer if part).strip()
        if combined:
            joined.append((start_line, combined))
    return joined


def detect_stack(target: Path) -> str:
    """Infer project packaging stack ('tauri', 'python-pyinstaller', or 'generic')."""
    tauri_markers = (
        target / "tauri.conf.json",
        target / "src-tauri" / "tauri.conf.json",
        target / "tauri.windows.bundle.json",
    )
    if any(p.is_file() for p in tauri_markers):
        return "tauri"

    cargo_toml = target / "src-tauri" / "Cargo.toml"
    if not cargo_toml.is_file():
        cargo_toml = target / "Cargo.toml"
    if cargo_toml.is_file() and "tauri" in cargo_toml.read_text(encoding="utf-8", errors="ignore").lower():
        return "tauri"

    for path in _iter_project_files(target):
        if path.suffix.lower() == ".spec" or "version_info" in path.name.lower() or path.name == "installer.iss":
            return "python-pyinstaller"
        if path.suffix.lower() in {".yml", ".yaml"} and ".github" in path.parts:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if "tauri" in text:
                return "tauri"
            if "pyinstaller" in text:
                return "python-pyinstaller"

    if (target / "pyproject.toml").is_file() or (target / "requirements.txt").is_file():
        return "python-pyinstaller"
    return "generic"


def _audit_upx_and_ci(
    target: Path,
    stack: str,
    spec_files: list[Path],
    findings: list[AuditFinding],
) -> None:
    """Inspect .spec files, scripts, and GitHub Actions workflows for UPX, onefile, and SHA256."""
    for spec in spec_files:
        rel = spec.relative_to(target).as_posix()
        text = spec.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            code = _strip_hash_comments(line)
            if re.search(r"\bupx\s*=\s*True\b", code):
                findings.append(
                    AuditFinding(
                        rule_id="UPX_ENABLED",
                        severity="HIGH",
                        message=f"UPX compression is enabled (`upx=True`) in {rel}.",
                        fix="Set `upx=False` in both EXE(...) and COLLECT(...) inside your .spec file.",
                        file_path=rel,
                        line_number=lineno,
                    )
                )
        if re.search(r"\bEXE\s*\(", text) and not re.search(r"\bCOLLECT\s*\(", text):
            findings.append(
                AuditFinding(
                    rule_id="PYINSTALLER_ONEFILE",
                    severity="MEDIUM",
                    message=f"Single-file EXE spec without COLLECT(...) detected in {rel}.",
                    fix="Switch to `--onedir --noupx` with COLLECT(...) and wrap with Inno Setup or WiX MSI.",
                    file_path=rel,
                )
            )

    spec_disables_upx = any(
        re.search(r"\bupx\s*=\s*False\b", _strip_hash_comments(p.read_text(encoding="utf-8", errors="ignore")))
        and not re.search(r"\bupx\s*=\s*True\b", _strip_hash_comments(p.read_text(encoding="utf-8", errors="ignore")))
        for p in spec_files
    )

    workflow_dir = target / ".github" / "workflows"
    workflows: list[Path] = []
    if workflow_dir.is_dir():
        workflows = sorted(
            p for p in workflow_dir.iterdir() if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
        )

    if not workflows:
        findings.append(
            AuditFinding(
                rule_id="MISSING_CI_WORKFLOW",
                severity="HIGH",
                message="No GitHub Actions workflow found under `.github/workflows/`.",
                fix="Run `crosspack_kit.py init --stack <tauri|python-pyinstaller>` to generate `.github/workflows/build-windows.yml`.",
                file_path=".github/workflows/",
            )
        )
    else:
        has_windows_runner = False
        has_sha256_step = False
        for wf in workflows:
            rel = wf.relative_to(target).as_posix()
            raw_text = wf.read_text(encoding="utf-8", errors="ignore")
            active_lines = [
                _strip_hash_comments(line) for line in raw_text.splitlines()
            ]
            active_text = "\n".join(active_lines)
            if re.search(r"windows-(latest|2022|2025|2019)", active_text, re.IGNORECASE):
                has_windows_runner = True
            if re.search(
                r"(SHA256SUMS\.txt|sha256sum|Get-FileHash|hashlib\.sha256|hashlib\.file_digest|certutil\s+-hashfile|crosspack_kit(?:\.py)?\s+checksums)",
                active_text,
                re.IGNORECASE,
            ):
                has_sha256_step = True

        if not has_windows_runner:
            findings.append(
                AuditFinding(
                    rule_id="MISSING_WINDOWS_RUNNER",
                    severity="HIGH",
                    message="No GitHub Actions workflow uses a `windows-latest` / Windows runner.",
                    fix="Configure `runs-on: windows-latest` so WiX MSI / PyInstaller Windows builds run natively on Windows.",
                    file_path=".github/workflows/",
                )
            )
        if not has_sha256_step:
            findings.append(
                AuditFinding(
                    rule_id="MISSING_SHA256_STEP",
                    severity="HIGH",
                    message="CI workflows lack a SHA256 checksum generation step (`SHA256SUMS.txt`).",
                    fix="Add a step generating `SHA256SUMS.txt` (via `crosspack_kit.py checksums` or `hashlib.sha256`) and attach it to Releases.",
                    file_path=workflows[0].relative_to(target).as_posix(),
                )
            )

    code_exts = {".yml", ".yaml", ".sh", ".ps1", ".bat", ".cmd", ".py"}
    pyinstaller_cmd_re = re.compile(
        r"(?:^|(?:&&|\|\||[;|&]|run:)\s*)(?:python(?:3)?\s+-m\s+|(?:uv|poetry|pipenv)\s+run\s+)?"
        r"(?:[\"']?[\w./\\:-]*[/\\])?pyinstaller(?:\.exe)?(?:\s+|$)",
        re.IGNORECASE,
    )
    yaml_meta_re = re.compile(r"^\s*(?:-\s*)?(?:name|description|id|uses|if)\s*:", re.IGNORECASE)

    for path in _iter_project_files(target):
        if path.suffix.lower() not in code_exts:
            continue
        if path.name in {"crosspack_kit.py", "test_crosspack_kit.py"}:
            continue
        is_yaml = path.suffix.lower() in {".yml", ".yaml"}
        rel = path.relative_to(target).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, cmd in _join_continued_lines(text):
            if is_yaml and yaml_meta_re.match(cmd):
                continue
            if re.search(r"--upx-dir\b", cmd):
                findings.append(
                    AuditFinding(
                        rule_id="UPX_ENABLED",
                        severity="HIGH",
                        message=f"UPX directory flag `--upx-dir` detected in {rel}.",
                        fix="Remove `--upx-dir` and pass `--noupx` to PyInstaller.",
                        file_path=rel,
                        line_number=lineno,
                    )
                )
            elif re.search(r"(?:^|[;&|]\s*|run:\s*)(?:choco|apt|apt-get|brew)\s+install[^\n]*\bupx\b", cmd, re.IGNORECASE):
                findings.append(
                    AuditFinding(
                        rule_id="UPX_ENABLED",
                        severity="HIGH",
                        message=f"UPX package installation detected in {rel}.",
                        fix="Do not install or invoke UPX on Windows distribution binaries.",
                        file_path=rel,
                        line_number=lineno,
                    )
                )
            elif re.search(r"(?:^|[;&|]\s*)upx(?:\.exe)?\s+(?:-\d|--best|--ultra-brute|-[a-zA-Z]*\s+\S+)", cmd):
                findings.append(
                    AuditFinding(
                        rule_id="UPX_ENABLED",
                        severity="HIGH",
                        message=f"Direct UPX packer invocation detected in {rel}.",
                        fix="Remove the UPX packing step; UPX-compressed binaries trigger 360/Defender heuristics.",
                        file_path=rel,
                        line_number=lineno,
                    )
                )

            if pyinstaller_cmd_re.search(cmd) and not re.search(
                r"\b(?:pip(?:3)?|uv\s+pip|conda|mamba)\s+install\b", cmd, re.IGNORECASE
            ):
                if re.search(r"(?:--onefile|\s-F(?:\s|$))", cmd):
                    findings.append(
                        AuditFinding(
                            rule_id="PYINSTALLER_ONEFILE",
                            severity="MEDIUM",
                            message=f"PyInstaller `--onefile` (`-F`) detected in {rel}.",
                            fix="Replace `--onefile` with `--onedir --noupx` and package with Inno Setup / WiX MSI.",
                            file_path=rel,
                            line_number=lineno,
                        )
                    )
                uses_spec = bool(re.search(r"\S+\.spec\b", cmd))
                has_noupx = bool(re.search(r"--noupx\b", cmd))
                if not has_noupx and not (uses_spec and spec_disables_upx):
                    findings.append(
                        AuditFinding(
                            rule_id="PYINSTALLER_MISSING_NOUPX",
                            severity="HIGH",
                            message=f"PyInstaller invocation without `--noupx` detected in {rel}.",
                            fix="Pass `--noupx` to `pyinstaller` (and set `upx=False` in `.spec`) to prevent UPX packing.",
                            file_path=rel,
                            line_number=lineno,
                        )
                    )


def _audit_manifest(target: Path, findings: list[AuditFinding]) -> None:
    """Check for a valid Windows UAC asInvoker application manifest."""
    manifests = sorted(
        p for p in _iter_project_files(target) if p.suffix.lower() == ".manifest"
    )
    if not manifests:
        findings.append(
            AuditFinding(
                rule_id="MISSING_UAC_MANIFEST",
                severity="HIGH",
                message="No Windows UAC manifest (`*.manifest`) found in project.",
                fix="Add `app.manifest` with `<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>`.",
                file_path="app.manifest",
            )
        )
        return

    for mf in manifests:
        rel = mf.relative_to(target).as_posix()
        try:
            root = ET.fromstring(mf.read_text(encoding="utf-8", errors="replace"))
        except ET.ParseError as exc:
            findings.append(
                AuditFinding(
                    rule_id="INVALID_UAC_MANIFEST",
                    severity="HIGH",
                    message=f"Malformed XML in manifest {rel}: {exc}",
                    fix="Regenerate `app.manifest` via `crosspack_kit.py init`.",
                    file_path=rel,
                )
            )
            continue

        levels = [
            elem.attrib.get("level", "")
            for elem in root.iter()
            if elem.tag.split("}")[-1] == "requestedExecutionLevel"
        ]
        if not levels:
            findings.append(
                AuditFinding(
                    rule_id="INVALID_UAC_MANIFEST",
                    severity="HIGH",
                    message=f"Manifest {rel} does not declare `<requestedExecutionLevel>`.",
                    fix="Add `<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>` inside `<trustInfo>`.",
                    file_path=rel,
                )
            )
        elif any(lvl in {"requireAdministrator", "highestAvailable"} for lvl in levels):
            findings.append(
                AuditFinding(
                    rule_id="ELEVATED_UAC_MANIFEST",
                    severity="MEDIUM",
                    message=f"Manifest {rel} requests elevated privileges ({', '.join(levels)}).",
                    fix="Use `level=\"asInvoker\"` unless your installer/app strictly requires system-wide admin rights.",
                    file_path=rel,
                )
            )
        elif "asInvoker" not in levels:
            findings.append(
                AuditFinding(
                    rule_id="INVALID_UAC_MANIFEST",
                    severity="HIGH",
                    message=f"Manifest {rel} specifies unexpected execution level: {', '.join(levels)}.",
                    fix="Set `<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>`.",
                    file_path=rel,
                )
            )


def _audit_pyinstaller_version_info(
    target: Path,
    spec_files: list[Path],
    findings: list[AuditFinding],
) -> None:
    """Validate PyInstaller PE version metadata file and fields."""
    version_files = sorted(
        p
        for p in _iter_project_files(target)
        if p.suffix.lower() == ".txt" and "version" in p.name.lower()
    )
    if not version_files:
        findings.append(
            AuditFinding(
                rule_id="MISSING_VERSION_METADATA",
                severity="HIGH",
                message="No `windows_version_info.txt` PE metadata file found for PyInstaller.",
                fix="Generate `windows_version_info.txt` via `crosspack_kit.py init --stack python-pyinstaller` and pass `--version-file`.",
                file_path="windows_version_info.txt",
            )
        )
        return

    vf = version_files[0]
    rel = vf.relative_to(target).as_posix()
    text = vf.read_text(encoding="utf-8", errors="ignore")
    missing_fields: list[str] = []
    for key in REQUIRED_VERSION_FIELDS:
        match = re.search(
            rf"StringStruct\(\s*u?['\"]{key}['\"]\s*,\s*u?(['\"])(.*?)\1\s*\)",
            text,
        )
        if not match or not match.group(2).strip():
            missing_fields.append(key)

    if missing_fields:
        findings.append(
            AuditFinding(
                rule_id="INCOMPLETE_VERSION_METADATA",
                severity="HIGH",
                message=f"Incomplete PE version metadata in {rel}; missing or empty: {', '.join(missing_fields)}.",
                fix="Populate CompanyName, FileDescription, ProductVersion, and LegalCopyright with valid non-empty strings.",
                file_path=rel,
            )
        )


def _audit_tauri_metadata(target: Path, findings: list[AuditFinding]) -> None:
    """Validate Tauri bundle metadata and installer targets."""
    candidates = (
        target / "src-tauri" / "tauri.conf.json",
        target / "tauri.conf.json",
        target / "tauri.windows.bundle.json",
    )
    cfg_path = next((p for p in candidates if p.is_file()), None)
    if cfg_path is None:
        findings.append(
            AuditFinding(
                rule_id="MISSING_VERSION_METADATA",
                severity="HIGH",
                message="No Tauri configuration (`tauri.conf.json` or `tauri.windows.bundle.json`) found.",
                fix="Add publisher, copyright, and shortDescription metadata under `bundle` in `tauri.conf.json`.",
                file_path="src-tauri/tauri.conf.json",
            )
        )
        return

    rel = cfg_path.relative_to(target).as_posix()
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(
            AuditFinding(
                rule_id="INVALID_TAURI_CONFIG",
                severity="HIGH",
                message=f"Invalid JSON in {rel}: {exc}",
                fix="Fix JSON syntax in Tauri configuration.",
                file_path=rel,
            )
        )
        return

    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        tauri_obj = data.get("tauri")
        bundle = tauri_obj.get("bundle") if isinstance(tauri_obj, dict) else None
    if not isinstance(bundle, dict):
        bundle = {}

    missing: list[str] = []
    for key in ("publisher", "copyright"):
        if not str(bundle.get(key, "")).strip():
            missing.append(key)
    if not (str(bundle.get("shortDescription", "")).strip() or str(bundle.get("longDescription", "")).strip()):
        missing.append("shortDescription")

    if missing:
        findings.append(
            AuditFinding(
                rule_id="MISSING_TAURI_METADATA",
                severity="HIGH",
                message=f"Missing Windows publisher/PE metadata in {rel}: {', '.join(missing)}.",
                fix="Set non-empty `bundle.publisher`, `bundle.copyright`, and `bundle.shortDescription` in `tauri.conf.json`.",
                file_path=rel,
            )
        )

    targets = bundle.get("targets")
    if isinstance(targets, list) and "nsis" in targets and "msi" not in targets:
        findings.append(
            AuditFinding(
                rule_id="NSIS_WITHOUT_MSI",
                severity="MEDIUM",
                message=f"Tauri targets in {rel} include `nsis` without `msi`.",
                fix="Add `msi` to `bundle.targets` (`[\"msi\", \"nsis\"]`). WiX `.msi` installers trigger far fewer 360 false positives than bare `setup.exe`.",
                file_path=rel,
            )
        )


def audit_project(target_dir: Path, stack: str = "auto") -> AuditReport:
    """Audit a project directory for Windows AV false-positive triggers."""
    target = target_dir.resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"Audit target directory does not exist: {target}")

    resolved_stack = detect_stack(target) if stack == "auto" else stack
    if resolved_stack not in (*SUPPORTED_STACKS, "generic"):
        raise ValueError(f"Unsupported stack '{stack}'.")

    findings: list[AuditFinding] = []
    spec_files = sorted(
        p for p in _iter_project_files(target) if p.suffix.lower() == ".spec"
    )

    _audit_upx_and_ci(target, resolved_stack, spec_files, findings)
    _audit_manifest(target, findings)

    if resolved_stack == "python-pyinstaller":
        _audit_pyinstaller_version_info(target, spec_files, findings)
    elif resolved_stack == "tauri":
        _audit_tauri_metadata(target, findings)
    else:
        has_version_txt = any(
            p.suffix.lower() == ".txt" and "version" in p.name.lower()
            for p in _iter_project_files(target)
        )
        has_tauri_cfg = any(
            (target / rel).is_file()
            for rel in ("src-tauri/tauri.conf.json", "tauri.conf.json", "tauri.windows.bundle.json")
        )
        if has_version_txt:
            _audit_pyinstaller_version_info(target, spec_files, findings)
        elif has_tauri_cfg:
            _audit_tauri_metadata(target, findings)
        else:
            findings.append(
                AuditFinding(
                    rule_id="MISSING_VERSION_METADATA",
                    severity="HIGH",
                    message="No PE version metadata (`windows_version_info.txt` or `tauri.conf.json`) found.",
                    fix="Run `crosspack_kit.py init --stack <tauri|python-pyinstaller>` to generate Windows metadata.",
                    file_path="windows_version_info.txt",
                )
            )

    has_blocking = any(f.severity in {"HIGH", "MEDIUM"} for f in findings)
    return AuditReport(
        target=str(target),
        detected_stack=resolved_stack,
        status="FAIL" if has_blocking else "PASS",
        findings=findings,
    )


def sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Compute lowercase hexadecimal SHA-256 digest of a file using bounded memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def generate_checksums(
    inputs: Sequence[Path],
    output_file: Path,
    base_dir: Path | None = None,
) -> list[tuple[str, str]]:
    """Compute SHA-256 checksums for input files/directories and write `SHA256SUMS.txt`."""
    resolved_output = output_file.resolve()
    resolved_base = (base_dir or resolved_output.parent).resolve()

    collected: dict[Path, str] = {}
    ignored_names = {resolved_output.name, ".DS_Store", "Thumbs.db"}

    for item in inputs:
        resolved_item = item.resolve()
        if not resolved_item.exists():
            raise FileNotFoundError(f"Checksum input path does not exist: {item}")

        if resolved_item.is_file():
            if resolved_item == resolved_output:
                continue
            try:
                rel_label = resolved_item.relative_to(resolved_base).as_posix()
            except ValueError:
                rel_label = resolved_item.name
            collected[resolved_item] = rel_label
        elif resolved_item.is_dir():
            for child in _iter_project_files(resolved_item):
                if child.resolve() == resolved_output or child.name in ignored_names:
                    continue
                try:
                    rel_label = child.resolve().relative_to(resolved_base).as_posix()
                except ValueError:
                    rel_label = child.resolve().relative_to(resolved_item).as_posix()
                collected[child.resolve()] = rel_label

    if not collected:
        raise ValueError("No artifact files found to hash.")

    entries: list[tuple[str, str]] = []
    for file_path, rel_label in sorted(collected.items(), key=lambda pair: pair[1]):
        entries.append((sha256_file(file_path), rel_label))

    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{digest}  {label}" for digest, label in entries]
    resolved_output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return entries


def verify_checksums(checksum_file: Path, base_dir: Path | None = None) -> tuple[bool, list[str]]:
    """Verify files against a `SHA256SUMS.txt` manifest."""
    resolved_manifest = checksum_file.resolve()
    if not resolved_manifest.is_file():
        raise FileNotFoundError(f"Checksum manifest does not exist: {checksum_file}")

    root = (base_dir or resolved_manifest.parent).resolve()
    errors: list[str] = []
    verified_count = 0

    for lineno, raw_line in enumerate(
        resolved_manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = raw_line.strip()
        if not stripped:
            continue
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?(.+)", stripped)
        if not match:
            errors.append(f"Line {lineno}: malformed SHA256SUMS entry: {raw_line}")
            continue
        expected_hash = match.group(1).lower()
        rel_path = match.group(2).strip()
        target_file = (root / rel_path).resolve()
        if not target_file.is_relative_to(root):
            errors.append(f"Unsafe path outside checksum root: {rel_path}")
            continue
        if not target_file.is_file():
            errors.append(f"Missing file: {rel_path}")
            continue
        actual_hash = sha256_file(target_file)
        if actual_hash != expected_hash:
            errors.append(
                f"Checksum mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )
            continue
        verified_count += 1

    if verified_count == 0 and not errors:
        errors.append("Checksum manifest is empty.")
    return len(errors) == 0, errors


def _format_audit_text(report: AuditReport) -> str:
    """Format an AuditReport as readable terminal output."""
    lines = [
        f"CrossPack Audit: {report.status}",
        f"Target: {report.target}",
        f"Stack:  {report.detected_stack}",
        f"Summary: {report.high_count} HIGH, {report.medium_count} MEDIUM, {report.info_count} INFO",
    ]
    if not report.findings:
        lines.append("All AV false-positive hygiene checks passed.")
        return "\n".join(lines)

    lines.append("")
    for idx, item in enumerate(report.findings, start=1):
        loc = item.file_path
        if item.line_number is not None:
            loc = f"{loc}:{item.line_number}"
        lines.append(f"{idx}. [{item.severity}] {item.rule_id} ({loc})")
        lines.append(f"   Problem: {item.message}")
        lines.append(f"   Fix:     {item.fix}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="crosspack_kit",
        description="Cross-platform Windows installer bundle generator, AV hygiene auditor, and SHA256 checksum tool.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Generate GitHub Actions CI + PE metadata + UAC manifest + AV checklist.",
    )
    init_parser.add_argument(
        "--stack",
        required=True,
        choices=SUPPORTED_STACKS,
        help="Target project stack.",
    )
    init_parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="Output project directory (default: current directory).",
    )
    init_parser.add_argument("--app-name", default="MyCrossApp", help="Application display name.")
    init_parser.add_argument("--publisher", default="Independent Developer", help="Publisher / company name.")
    init_parser.add_argument(
        "--version",
        "--app-version",
        dest="app_version",
        default="0.1.0",
        help="Application semantic version (default: 0.1.0).",
    )
    init_parser.add_argument(
        "--description",
        default="Cross-platform desktop application",
        help="Short application description for PE metadata.",
    )
    init_parser.add_argument(
        "--entry",
        default="main.py",
        help="Python entrypoint script for python-pyinstaller (default: main.py).",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing generated files if present.",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Scan a project directory for AV false-positive triggers.",
    )
    audit_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to audit (default: current directory).",
    )
    audit_parser.add_argument(
        "--stack",
        default="auto",
        choices=("auto", *SUPPORTED_STACKS, "generic"),
        help="Force stack detection or use auto (default: auto).",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print audit report as JSON.",
    )
    audit_parser.add_argument(
        "--allow-medium",
        action="store_true",
        help="Exit 0 when only MEDIUM/INFO warnings exist (still fail on HIGH).",
    )

    sum_parser = subparsers.add_parser(
        "checksums",
        help="Generate or verify SHA256SUMS.txt for release artifacts.",
    )
    sum_parser.add_argument(
        "inputs",
        nargs="*",
        default=["."],
        help="Artifact files or directories to hash (default: current directory).",
    )
    sum_parser.add_argument(
        "-o",
        "--output",
        default="SHA256SUMS.txt",
        help="Output checksum manifest path (default: SHA256SUMS.txt).",
    )
    sum_parser.add_argument(
        "--base-dir",
        default=None,
        help="Base directory for relative paths inside SHA256SUMS.txt.",
    )
    sum_parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify files against the specified checksum manifest (`--output`).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint returning an integer exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            written = init_bundle(
                stack=args.stack,
                output_dir=Path(args.output),
                app_name=args.app_name,
                publisher=args.publisher,
                version=args.app_version,
                description=args.description,
                entry=args.entry,
                force=args.force,
            )
            print(f"Initialized {args.stack} Windows cross-packaging bundle ({len(written)} files):")
            for path in written:
                print(f"  - {path}")
            return 0

        if args.command == "audit":
            report = audit_project(Path(args.path), stack=args.stack)
            if args.json_output:
                print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
            else:
                print(_format_audit_text(report))
            if args.allow_medium:
                return 1 if report.high_count > 0 else 0
            return 1 if report.status != "PASS" else 0

        if args.command == "checksums":
            output_path = Path(args.output)
            base_dir = Path(args.base_dir) if args.base_dir else None
            if args.verify:
                ok, errors = verify_checksums(output_path, base_dir=base_dir)
                if ok:
                    print(f"Checksum verification passed: {output_path}")
                    return 0
                for err in errors:
                    print(f"ERROR: {err}", file=sys.stderr)
                return 1

            entries = generate_checksums(
                inputs=[Path(p) for p in args.inputs],
                output_file=output_path,
                base_dir=base_dir,
            )
            print(f"Wrote {len(entries)} SHA-256 entries to {output_path}:")
            for digest, label in entries:
                print(f"  {digest}  {label}")
            return 0
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
