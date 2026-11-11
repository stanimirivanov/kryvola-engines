"""CI mirror bypass and fail-closed SP1 prerequisite installation."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import install_sp1_host


class Sp1HostInstallationTests(unittest.TestCase):
    def test_azure_is_removed_and_apt_remains_bounded_and_required(self):
        with tempfile.TemporaryDirectory() as directory:
            mirrors = Path(directory) / "apt-mirrors.txt"
            mirrors.write_text(
                "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://archive.ubuntu.com/ubuntu/\tpriority:2\nhttps://security.ubuntu.com/ubuntu/\tpriority:3\n"
            )
            with patch("subprocess.run") as run:
                install_sp1_host.install(mirrors)
            self.assertNotIn("azure.archive.ubuntu.com", mirrors.read_text())
            self.assertIn("https://archive.ubuntu.com/ubuntu/", mirrors.read_text())
            self.assertIn("https://security.ubuntu.com/ubuntu/", mirrors.read_text())
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 3)
            self.assertEqual(commands[-1], ["protoc", "--version"])
            for call in run.call_args_list:
                self.assertTrue(call.kwargs["check"])
                self.assertLessEqual(call.kwargs["timeout"], 180)
            for command in commands[:2]:
                self.assertIn("Acquire::Retries=3", command)
                self.assertIn("Acquire::https::Timeout=20", command)
            self.assertIn("APT::Update::Error-Mode=any", commands[0])
            self.assertEqual(commands[0][-1], "update")
            self.assertEqual(commands[1][-2:], ["protobuf-compiler", "libprotobuf-dev"])
            with patch("subprocess.run"):
                install_sp1_host.install(mirrors)  # Repeated setup remains usable.

    def test_failed_update_or_install_stops_before_using_protoc(self):
        for failure_at in (0, 1):
            with tempfile.TemporaryDirectory() as directory:
                mirrors = Path(directory) / "apt-mirrors.txt"
                mirrors.write_text("https://archive.ubuntu.com/ubuntu/\n")
                effects = [None] * failure_at + [subprocess.CalledProcessError(100, "apt-get")]
                with patch("subprocess.run", side_effect=effects) as run:
                    with self.assertRaises(subprocess.CalledProcessError):
                        install_sp1_host.install(mirrors)
                self.assertEqual(run.call_count, failure_at + 1)

    def test_missing_official_fallback_does_not_edit_or_install(self):
        with tempfile.TemporaryDirectory() as directory:
            mirrors = Path(directory) / "apt-mirrors.txt"
            original = "http://azure.archive.ubuntu.com/ubuntu/\n"
            mirrors.write_text(original)
            with patch("subprocess.run") as run:
                with self.assertRaises(ValueError):
                    install_sp1_host.install(mirrors)
                run.assert_not_called()
            self.assertEqual(mirrors.read_text(), original)
