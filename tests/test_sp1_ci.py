"""Offline transfer controls; fixture bytes are never native proof evidence."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools import sp1_ci


class GuestTransferTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.revision = "a" * 40
        for name in sp1_ci.ELFS:
            (self.root / name).write_bytes(b"\x7fELFtest-only-" + name.encode())
        self.digest = sp1_ci.write_manifest(self.root, self.revision)

    def test_round_trip_and_context_binding(self):
        sp1_ci.verify_guests(self.root, self.revision, self.digest)
        for revision, digest in (
            ("b" * 40, self.digest),
            (self.revision, "0" * 64),
            (self.revision, ""),
        ):
            with self.subTest(revision=revision, digest=digest), self.assertRaises(ValueError):
                sp1_ci.verify_guests(self.root, revision, digest)

    def test_reject_changed_missing_extra_and_symlinked_guests(self):
        path = self.root / sp1_ci.ELFS[0]
        original = path.read_bytes()
        path.write_bytes(original + b"tampered")
        with self.assertRaises(ValueError):
            sp1_ci.verify_guests(self.root, self.revision, self.digest)
        path.unlink()
        with self.assertRaises(ValueError):
            sp1_ci.verify_guests(self.root, self.revision, self.digest)
        path.symlink_to(self.root / sp1_ci.ELFS[1])
        with self.assertRaises(ValueError):
            sp1_ci.verify_guests(self.root, self.revision, self.digest)
        path.unlink()
        path.write_bytes(original)
        (self.root / "unexpected").write_text("extra")
        with self.assertRaises(ValueError):
            sp1_ci.verify_guests(self.root, self.revision, self.digest)

    def test_reject_substituted_toolchain_even_with_rehashed_manifest(self):
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["image"] = "unapproved"
        raw = json.dumps(manifest).encode()
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            sp1_ci.verify_guests(self.root, self.revision, hashlib.sha256(raw).hexdigest())


class MeasurementTests(unittest.TestCase):
    def test_both_fifo_samples_use_the_same_bound_binary(self):
        from unittest.mock import patch

        from tests.test_sp1_relation import fixture

        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "host"
            binary.write_bytes(b"unit-test-only-not-an-executable")
            with patch.object(sp1_ci.sp1_relation, "execute", return_value=fixture()) as execute:
                result = sp1_ci.measure(binary)
            self.assertEqual(execute.call_count, 2)
            self.assertTrue(all(call.args == (binary,) for call in execute.call_args_list))
            self.assertEqual(result["native_binary_sha256"], sp1_ci.sha256(binary))
            self.assertEqual([row["index"] for row in result["samples"]], [0, 1])
            self.assertGreaterEqual(
                result["samples"][1]["queue_ns"], result["samples"][0]["end_to_end_ns"]
            )
            self.assertFalse(result["production_qualified"])

    def test_bad_artifacts_stop_before_host_build_or_qualification(self):
        from unittest.mock import patch

        from tools import qualify_release, release

        with (
            patch.object(sp1_ci.proof_modes, "configuration"),
            patch.object(sp1_ci, "revision", return_value="a" * 40),
            patch.object(sp1_ci, "verify_guests", side_effect=ValueError("bad artifact")),
            patch.object(sp1_ci, "build_host") as host,
            patch.object(release, "install") as install,
            patch.object(qualify_release, "qualify") as qualify,
        ):
            for consumer in (sp1_ci.measurements, sp1_ci.qualification):
                with self.assertRaises(ValueError):
                    consumer("0" * 64)
            host.assert_not_called()
            install.assert_not_called()
            qualify.assert_not_called()


class GuestBuildTests(unittest.TestCase):
    def archive(self, duplicate=False):
        import io
        import tarfile

        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for _ in range(2 if duplicate else 1):
                entry = tarfile.TarInfo("bin/cargo-prove")
                entry.size = 4
                archive.addfile(entry, io.BytesIO(b"test"))
        return output.getvalue()

    def test_builds_both_guests_with_pinned_docker_and_locked_dependencies(self):
        import io
        from unittest.mock import patch

        raw = self.archive()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "elf"

            def build(command, cwd, env, timeout):
                self.assertIn("--docker", command)
                self.assertIn("--locked", command)
                self.assertEqual(env["SP1_DOCKER_IMAGE"], sp1_ci.sp1_relation.IMAGE)
                self.assertEqual(timeout, 1800)
                name = command[command.index("--elf-name") + 1]
                (directory / name).write_bytes(b"test-only-elf")

            with (
                patch.object(sp1_ci, "ELF_DIR", directory),
                patch.object(sp1_ci, "configuration"),
                patch.object(sp1_ci, "revision", return_value="a" * 40),
                patch.object(sp1_ci.sp1_relation, "CLI_SHA256", hashlib.sha256(raw).hexdigest()),
                patch.object(sp1_ci.urllib.request, "urlopen", return_value=io.BytesIO(raw)),
                patch.object(sp1_ci.sp1_relation, "_run", side_effect=build) as run,
            ):
                digest = sp1_ci.build_guests()
                sp1_ci.verify_guests(directory, "a" * 40, digest)
                self.assertEqual(run.call_count, 2)

    def test_bad_cli_hash_or_duplicate_executable_never_runs(self):
        import io
        from unittest.mock import patch

        for duplicate in (False, True):
            raw = self.archive(duplicate)
            expected = hashlib.sha256(raw).hexdigest() if duplicate else "0" * 64
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(sp1_ci, "ELF_DIR", Path(temporary) / "elf"),
                patch.object(sp1_ci, "configuration"),
                patch.object(sp1_ci.sp1_relation, "CLI_SHA256", expected),
                patch.object(sp1_ci.urllib.request, "urlopen", return_value=io.BytesIO(raw)),
                patch.object(sp1_ci.sp1_relation, "_run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "CLI_ARCHIVE|CLI_CHECKSUM"):
                    sp1_ci.build_guests()
                run.assert_not_called()
