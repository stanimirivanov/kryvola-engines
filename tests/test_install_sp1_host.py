"""Mirror-independent, checksum-pinned protoc installation and cache controls."""

import hashlib
import io
import subprocess
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from tools import install_sp1_host as setup


def fixture():
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("bin/protoc", b"compiler fixture")
        archive.writestr("include/google/protobuf/empty.proto", b"syntax = 'proto3';")
    return buffer.getvalue()


class Sp1HostInstallationTests(unittest.TestCase):
    def test_runner_python_312_syntax(self):
        import ast

        ast.parse(Path(setup.__file__).read_text(), feature_version=(3, 12))

    def test_installs_compiler_and_includes_without_apt_or_sudo(self):
        raw = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, env, paths = root / "protoc", root / "env", root / "paths"
            with (
                patch.object(setup, "SHA256", hashlib.sha256(raw).hexdigest()),
                patch.object(setup, "download", return_value=raw) as fetch,
                patch.dict("os.environ", {"GITHUB_ENV": str(env), "GITHUB_PATH": str(paths)}),
                patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, "libprotoc 3.21.12\n"),
                ) as run,
            ):
                setup.install(output)
                self.assertEqual((output / "bin/protoc").read_bytes(), b"compiler fixture")
                self.assertTrue((output / "include/google/protobuf/empty.proto").is_file())
                self.assertEqual((output / "bin/protoc").stat().st_mode & 0o777, 0o755)
                self.assertIn("PROTOC_INCLUDE=" + str(output / "include"), env.read_text())
                self.assertIn("PROTOC=" + str(output / "bin/protoc"), env.read_text())
                self.assertEqual(paths.read_text(), str(output / "bin") + "\n")
                self.assertEqual(run.call_args.args[0], [str(output / "bin/protoc"), "--version"])
                setup.install(output)
                fetch.assert_called_once()
                (output / "bin/protoc").write_bytes(b"tampered")
                with self.assertRaises(ValueError):
                    setup.install(output)

    def test_bad_download_does_not_install_or_export(self):
        with tempfile.TemporaryDirectory() as directory:
            output, env = Path(directory) / "protoc", Path(directory) / "env"
            with (
                patch.object(setup, "download", return_value=b"corrupt"),
                patch.dict("os.environ", {"GITHUB_ENV": str(env)}),
            ):
                with self.assertRaises(ValueError):
                    setup.install(output)
            self.assertFalse(output.exists())
            self.assertFalse(env.exists())

    def test_download_retries_transient_failures_but_not_permanent_errors(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError), patch("time.sleep"):
            with self.assertRaises(TimeoutError):
                setup.download()
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(setup.URL, 404, "missing", Message(), None),
        ) as fetch:
            with self.assertRaises(urllib.error.HTTPError):
                setup.download()
            self.assertEqual(fetch.call_count, 1)

    def test_invalid_version_and_unsafe_zip_are_rejected(self):
        raw = fixture()
        with tempfile.TemporaryDirectory() as directory:
            output, env = Path(directory) / "protoc", Path(directory) / "env"
            with (
                patch.object(setup, "SHA256", hashlib.sha256(raw).hexdigest()),
                patch.object(setup, "download", return_value=raw),
                patch.dict("os.environ", {"GITHUB_ENV": str(env)}),
                patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, "libprotoc 99\n"),
                ),
            ):
                with self.assertRaises(ValueError):
                    setup.install(output)
                self.assertFalse(env.exists())
        buffer = io.BytesIO()
        with ZipFile(buffer, "w") as archive:
            archive.writestr("../escape", b"fixture")
        raw = buffer.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(setup, "SHA256", hashlib.sha256(raw).hexdigest()),
                patch.object(setup, "download", return_value=raw),
            ):
                with self.assertRaises(ValueError):
                    setup.install(Path(directory) / "protoc")
