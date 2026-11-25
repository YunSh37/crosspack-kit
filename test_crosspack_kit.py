"""Comprehensive unittest suite for crosspack_kit."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import crosspack_kit


class TestCrossPackInit(unittest.TestCase):
    """Tests for `crosspack_kit.py init` on both supported stacks."""

    def test_init_python_pyinstaller_bundle_passes_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = crosspack_kit.main(
                    [
                        "init",
                        "--stack",
                        "python-pyinstaller",
                        "--output",
                        str(root),
                        "--app-name",
                        "Demo Tool",
                        "--publisher",
                        "Acme Lab",
                        "--version",
                        "1.2.3",
                        "--description",
                        "Demo desktop utility",
                        "--entry",
                        "src/main.py",
                    ]
                )
            self.assertEqual(exit_code, 0)

            expected_files = [
                ".github/workflows/build-windows.yml",
                "windows_version_info.txt",
                "app.manifest",
                "app.spec",
                "installer.iss",
                "SIGNING_AND_AV_CHECKLIST.md",
            ]
            for rel in expected_files:
                self.assertTrue((root / rel).is_file(), f"Missing generated file: {rel}")

            ver_text = (root / "windows_version_info.txt").read_text(encoding="utf-8")
            ast.parse(ver_text)  # Must be valid Python AST for PyInstaller
            self.assertIn("'CompanyName', 'Acme Lab'", ver_text)
            self.assertIn("'FileDescription', 'Demo desktop utility'", ver_text)
            self.assertIn("'ProductVersion', '1.2.3'", ver_text)
            self.assertIn("'LegalCopyright', 'Copyright (c) 2026 Acme Lab'", ver_text)

            manifest_root = ET.fromstring((root / "app.manifest").read_text(encoding="utf-8"))
            levels = [
                el.attrib.get("level")
                for el in manifest_root.iter()
                if el.tag.endswith("requestedExecutionLevel")
            ]
            self.assertEqual(levels, ["asInvoker"])

            spec_text = (root / "app.spec").read_text(encoding="utf-8")
            self.assertIn("upx=False", spec_text)
            self.assertIn("COLLECT(", spec_text)
            self.assertIn("'src/main.py'", spec_text)

            wf_text = (root / ".github/workflows/build-windows.yml").read_text(encoding="utf-8")
            self.assertIn("windows-latest", wf_text)
            self.assertIn("--noupx", wf_text)
            self.assertIn("SHA256SUMS.txt", wf_text)

            checklist = (root / "SIGNING_AND_AV_CHECKLIST.md").read_text(encoding="utf-8")
            self.assertIn("https://signpath.org", checklist)
            self.assertIn("https://www.microsoft.com/wdsi/filesubmission", checklist)
            self.assertIn("https://open.soft.360.cn/report.php", checklist)
            self.assertIn("https://learn.microsoft.com/en-us/azure/artifact-signing/", checklist)

            report = crosspack_kit.audit_project(root)
            self.assertEqual(report.detected_stack, "python-pyinstaller")
            self.assertEqual(report.status, "PASS", msg=f"Unexpected findings: {report.findings}")
            self.assertEqual(report.findings, [])

    def test_init_tauri_bundle_passes_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = crosspack_kit.main(
                    [
                        "init",
                        "--stack",
                        "tauri",
                        "--output",
                        str(root),
                        "--app-name",
                        "TauriNotes",
                        "--publisher",
                        "Studio X",
                        "--app-version",
                        "0.4.2",
                    ]
                )
            self.assertEqual(exit_code, 0)

            for rel in (
                ".github/workflows/build-windows.yml",
                "app.manifest",
                "tauri.windows.bundle.json",
                "src-tauri-build.rs.example",
                "SIGNING_AND_AV_CHECKLIST.md",
            ):
                self.assertTrue((root / rel).is_file(), f"Missing generated file: {rel}")

            bundle_cfg = json.loads((root / "tauri.windows.bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(bundle_cfg["bundle"]["publisher"], "Studio X")
            self.assertEqual(bundle_cfg["bundle"]["targets"], ["msi", "nsis"])
            self.assertIn("Copyright", bundle_cfg["bundle"]["copyright"])

            wf_text = (root / ".github/workflows/build-windows.yml").read_text(encoding="utf-8")
            self.assertIn("windows-latest", wf_text)
            self.assertIn("--bundles msi,nsis", wf_text)
            self.assertIn("SHA256SUMS.txt", wf_text)

            report = crosspack_kit.audit_project(root)
            self.assertEqual(report.detected_stack, "tauri")
            self.assertEqual(report.status, "PASS", msg=f"Unexpected findings: {report.findings}")
            self.assertEqual(report.findings, [])

    def test_init_overwrite_protection_and_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout):
                first = crosspack_kit.main(["init", "--stack", "tauri", "-o", str(root)])
            self.assertEqual(first, 0)

            with redirect_stderr(stderr):
                second = crosspack_kit.main(["init", "--stack", "tauri", "-o", str(root)])
            self.assertEqual(second, 1)
            self.assertIn("--force", stderr.getvalue())

            with redirect_stdout(stdout):
                third = crosspack_kit.main(["init", "--stack", "tauri", "-o", str(root), "--force"])
            self.assertEqual(third, 0)

    def test_init_invalid_version_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = crosspack_kit.main(
                    ["init", "--stack", "tauri", "-o", tmp, "--version", "bad-ver"]
                )
            self.assertEqual(code, 1)
            self.assertIn("Invalid version", stderr.getvalue())


class TestCrossPackAudit(unittest.TestCase):
    """Tests for `crosspack_kit.py audit` AV trigger detection."""

    def test_audit_catches_upx_onefile_missing_manifest_metadata_and_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "build.yml").write_text(
                "name: Bad Build\n"
                "on: [push]\n"
                "jobs:\n"
                "  win:\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: |\n"
                "          pyinstaller `\n"
                "            --onefile `\n"
                "            --upx-dir C:\\upx `\n"
                "            main.py\n",
                encoding="utf-8",
            )
            (root / "bad.spec").write_text(
                "exe = EXE(pyz, a.scripts, a.binaries, a.datas, name='app', upx=True)\n",
                encoding="utf-8",
            )
            (root / "build.sh").write_text(
                "#!/usr/bin/env bash\npython -m PyInstaller --onefile main.py\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = crosspack_kit.main(["audit", str(root), "--json"])
            self.assertEqual(exit_code, 1)

            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "FAIL")
            rule_ids = {item["rule_id"] for item in payload["findings"]}
            self.assertIn("UPX_ENABLED", rule_ids)
            self.assertIn("PYINSTALLER_ONEFILE", rule_ids)
            self.assertIn("PYINSTALLER_MISSING_NOUPX", rule_ids)
            self.assertIn("MISSING_SHA256_STEP", rule_ids)
            self.assertIn("MISSING_UAC_MANIFEST", rule_ids)
            self.assertIn("MISSING_VERSION_METADATA", rule_ids)

    def test_audit_ignores_upx_mentions_in_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crosspack_kit.init_bundle("python-pyinstaller", root)
            spec_path = root / "app.spec"
            spec_path.write_text(
                "# Never set upx=True or --onefile here\n" + spec_path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            wf_path = root / ".github/workflows/build-windows.yml"
            wf_path.write_text(
                "# Avoid upx --best and avoid --upx-dir\n" + wf_path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )

            report = crosspack_kit.audit_project(root)
            self.assertEqual(report.status, "PASS", msg=f"False positive findings: {report.findings}")

    def test_audit_catches_manifest_issues_and_incomplete_version_info(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crosspack_kit.init_bundle("python-pyinstaller", root)

            (root / "app.manifest").write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
                '  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\n'
                "    <security><requestedPrivileges>\n"
                '      <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>\n'
                "    </requestedPrivileges></security>\n"
                "  </trustInfo>\n"
                "</assembly>\n",
                encoding="utf-8",
            )
            ver_path = root / "windows_version_info.txt"
            ver_path.write_text(
                ver_path.read_text(encoding="utf-8").replace("'Independent Developer'", "''"),
                encoding="utf-8",
            )

            report = crosspack_kit.audit_project(root)
            rule_ids = {f.rule_id for f in report.findings}
            self.assertIn("ELEVATED_UAC_MANIFEST", rule_ids)
            self.assertIn("INCOMPLETE_VERSION_METADATA", rule_ids)

            (root / "app.manifest").write_text("<broken-xml", encoding="utf-8")
            report_malformed = crosspack_kit.audit_project(root)
            self.assertIn("INVALID_UAC_MANIFEST", {f.rule_id for f in report_malformed.findings})

    def test_audit_catches_tauri_missing_metadata_and_nsis_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src-tauri").mkdir(parents=True)
            (root / "src-tauri" / "tauri.conf.json").write_text(
                json.dumps(
                    {
                        "productName": "Demo",
                        "version": "0.1.0",
                        "bundle": {
                            "active": True,
                            "targets": ["nsis"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "release.yml").write_text(
                "jobs:\n  build:\n    runs-on: windows-latest\n    steps:\n      - run: npx tauri build\n",
                encoding="utf-8",
            )

            report = crosspack_kit.audit_project(root)
            self.assertEqual(report.detected_stack, "tauri")
            self.assertEqual(report.status, "FAIL")
            rule_ids = {f.rule_id for f in report.findings}
            self.assertIn("MISSING_TAURI_METADATA", rule_ids)
            self.assertIn("NSIS_WITHOUT_MSI", rule_ids)
            self.assertIn("MISSING_SHA256_STEP", rule_ids)
            self.assertIn("MISSING_UAC_MANIFEST", rule_ids)


class TestCrossPackChecksums(unittest.TestCase):
    """Tests for `crosspack_kit.py checksums` generation and verification."""

    def test_generate_and_verify_checksums_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp) / "release"
            sub_dir = release_dir / "msi"
            sub_dir.mkdir(parents=True)

            exe_file = release_dir / "demo-setup.exe"
            msi_file = sub_dir / "demo-x64.msi"
            exe_file.write_bytes(b"simulated-installer-payload-1")
            msi_file.write_bytes(b"simulated-msi-payload-2")

            manifest = release_dir / "SHA256SUMS.txt"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code1 = crosspack_kit.main(["checksums", str(release_dir), "-o", str(manifest)])
                # Second run must ignore existing SHA256SUMS.txt itself
                code2 = crosspack_kit.main(["checksums", str(release_dir), "-o", str(manifest)])
            self.assertEqual(code1, 0)
            self.assertEqual(code2, 0)

            lines = manifest.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(
                lines[0],
                f"{hashlib.sha256(b'simulated-installer-payload-1').hexdigest()}  demo-setup.exe",
            )
            self.assertEqual(
                lines[1],
                f"{hashlib.sha256(b'simulated-msi-payload-2').hexdigest()}  msi/demo-x64.msi",
            )

            with redirect_stdout(stdout):
                verify_ok = crosspack_kit.main(["checksums", "--verify", "-o", str(manifest)])
            self.assertEqual(verify_ok, 0)

            # Tamper artifact -> verification must fail
            exe_file.write_bytes(b"tampered")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                verify_fail = crosspack_kit.main(["checksums", "--verify", "-o", str(manifest)])
            self.assertEqual(verify_fail, 1)
            self.assertIn("Checksum mismatch", stderr.getvalue())

    def test_verify_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "SHA256SUMS.txt"
            manifest.write_text(("a" * 64) + "  ../escape.txt\n", encoding="utf-8")
            ok, errors = crosspack_kit.verify_checksums(manifest)
            self.assertFalse(ok)
            self.assertTrue(any("Unsafe path" in err for err in errors))


if __name__ == "__main__":
    unittest.main()
