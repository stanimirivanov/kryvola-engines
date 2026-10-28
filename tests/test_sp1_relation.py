"""Offline statement/report/mode controls; real SP1 proofs are required on CI."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import sp1_relation
from tools.sp1_relation import JOURNAL_BYTES, ROOT, configuration, report


def fixture():
    return {
        "experiment": "sp1-relation",
        "mode": "CORE_CPU",
        "outcome": 0,
        "negative_cases": 7,
        "elf_blake3": "a" * 64,
        "vk_digest": "b" * 64,
        "journal_blake3": "c" * 64,
        "journal_bytes": JOURNAL_BYTES,
        "proof_bytes": 100,
        "cycle_limit": 1_000_000,
        "prove_ns": 10,
        "verify_ns": 2,
        "total_ns": 20,
    }


class Sp1RelationTests(unittest.TestCase):
    def test_host_build_and_launch_survive_a_blocked_docker_target(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            member = tarfile.TarInfo("cargo-prove")
            member.size = 3
            tar.addfile(member, io.BytesIO(b"cli"))
        raw = archive.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "experiments/sp1"
            (work / "guest").mkdir(parents=True)
            # A file at this location blocks all host writes below the guest's target.
            (work / "target").write_text("Docker-owned target")
            calls = []

            def simulate(command, cwd, env, timeout, **kwargs):
                calls.append(command)
                if "--docker" in command:
                    destination = Path(command[command.index("--output-directory") + 1])
                    (destination / command[command.index("--elf-name") + 1]).write_bytes(b"elf")
                elif command[0] == "cargo":
                    self.assertEqual(env["PROTOC"], "/usr/bin/protoc")
                    destination = Path(command[command.index("--target-dir") + 1])
                    self.assertFalse(destination.is_relative_to(work / "target"))
                    (destination / "release").mkdir()
                    (destination / "release/kryvola-sp1-host").write_bytes(b"host")
                else:
                    self.assertTrue(Path(command[0]).is_file())
                    kwargs["stdout"].write(json.dumps(fixture()).encode())

            with (
                patch.object(sp1_relation, "ROOT", root),
                patch.object(sp1_relation, "WORK", work),
                patch.object(sp1_relation, "CLI_SHA256", hashlib.sha256(raw).hexdigest()),
                patch.object(sp1_relation.platform, "system", return_value="Linux"),
                patch.object(sp1_relation.platform, "machine", return_value="x86_64"),
                patch.object(sp1_relation.shutil, "which", return_value="/usr/bin/protoc"),
                patch.object(sp1_relation.urllib.request, "urlopen", return_value=io.BytesIO(raw)),
                patch.object(sp1_relation, "_run", side_effect=simulate),
            ):
                self.assertEqual(sp1_relation.execute(), fixture())
            self.assertEqual(len(calls), 4)
            self.assertEqual((work / "target").read_text(), "Docker-owned target")

    def test_missing_protoc_fails_before_download_or_build(self):
        with (
            patch.object(sp1_relation.platform, "system", return_value="Linux"),
            patch.object(sp1_relation.platform, "machine", return_value="x86_64"),
            patch.object(sp1_relation.shutil, "which", return_value=None),
            patch.object(sp1_relation.urllib.request, "urlopen") as download,
            patch.object(sp1_relation, "_run") as build,
        ):
            with self.assertRaisesRegex(ValueError, "SP1_PROTOC_REQUIRED"):
                sp1_relation.execute()
            download.assert_not_called()
            build.assert_not_called()

    def test_closed_report_rejects_wrong_modes_bindings_limits_and_outcomes(self):
        self.assertEqual(report(json.dumps(fixture()).encode()), fixture())
        for change in (
            {"mode": "MOCK"},
            {"outcome": 1},
            {"outcome": False},
            {"negative_cases": 6},
            {"vk_digest": "unknown"},
            {"journal_bytes": JOURNAL_BYTES + 1},
            {"proof_bytes": 0},
            {"proof_bytes": (128 << 20) + 1},
            {"cycle_limit": 0},
            {"prove_ns": -1},
            {"total_ns": 1},
            {"private_witness": "forbidden"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                report(json.dumps({**fixture(), **change}).encode())
        with self.assertRaises(ValueError):
            report(b'{"outcome":0,"outcome":0}')
        with self.assertRaises(ValueError):
            report(b" " * 8193)

    def test_mock_dev_and_ambient_compiler_modes_fail_before_execution(self):
        for overrides in (
            {"SP1_PROVER": "mock"},
            {"SP1_PROVER": "network"},
            {"SP1_DEV_MODE": "1"},
            {"SP1_DOCKER_IMAGE": "untrusted"},
            {"CARGO_TARGET_DIR": "untrusted"},
        ):
            with patch.dict(os.environ, overrides), self.assertRaises(ValueError):
                configuration()

    def test_configuration_is_not_native_success(self):
        value = subprocess.run(
            [sys.executable, "tools/feasibility.py", "sp1-relation", "--check-only"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
        self.assertEqual(
            json.loads(value.stdout),
            {
                "experiment": "sp1-relation",
                "status": "configuration_only",
                "native_executed": False,
            },
        )
