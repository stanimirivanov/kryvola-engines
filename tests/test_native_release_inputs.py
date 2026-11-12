"""M1 assembly must inspect and package the isolated native subjects."""

import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import m1_release as m1
from tools import native_build


class NativeReleaseInputTests(unittest.TestCase):
    def test_assembly_packages_the_same_workers_and_wheel_it_qualified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts, candidate = root / "native", root / "candidate"
            artifacts.mkdir()
            candidate.mkdir()
            (artifacts / "kryvola-cpu-engine").write_bytes(b"isolated engine")
            (artifacts / "kryvola-cpu-evaluator").write_bytes(b"isolated evaluator")
            wheel = artifacts / "kryvola_owner-0.1.0.dev2-cp314-cp314-linux_x86_64.whl"
            wheel.write_bytes(b"isolated owner wheel")

            def external(*args, **kwargs):
                (candidate / "sbom.json").write_text("{}")

            with (
                patch.object(m1, "OUTPUT", candidate),
                patch.object(m1.release, "run", side_effect=external),
                patch.object(m1, "image_identity", return_value="0" * 64),
                patch.object(m1, "image_check") as image_check,
                patch.object(m1.owner_wheel, "install_and_test") as installed,
            ):
                m1.assemble("a" * 40, {}, artifacts)
            self.assertEqual(installed.call_args.args[0], wheel)
            contents = m1.unpack(candidate / "cpu-runtime.tar", m1.CPU_FILES, 128 << 20)
            self.assertEqual(contents["kryvola-cpu-engine"], b"isolated engine")
            self.assertEqual(contents["kryvola-cpu-evaluator"], b"isolated evaluator")
            self.assertEqual(image_check.call_args.args[1], contents)
            self.assertEqual((candidate / wheel.name).read_bytes(), b"isolated owner wheel")

    def test_native_image_pins_match_repository_toolchain_versions(self):
        root = native_build.ROOT
        recipe = native_build.RECIPE.read_text()
        rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        uv = tomllib.loads((root / "pyproject.toml").read_text())["tool"]["uv"][
            "required-version"
        ].removeprefix("==")
        python = (root / ".python-version").read_text().strip()
        for prefix in (
            f"rust:{rust}-trixie",
            f"ghcr.io/astral-sh/uv:{uv}",
            f"python:{python}-trixie",
        ):
            self.assertRegex(recipe, prefix.replace(".", r"\.") + r"@sha256:[0-9a-f]{64}")
        self.assertIn(f"RUSTUP_TOOLCHAIN={rust}", recipe)

    def test_build_failure_cleans_only_its_named_container_without_host_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(native_build, "run", side_effect=RuntimeError("build failed")) as run,
                patch.object(native_build.subprocess, "run") as cleanup,
            ):
                with self.assertRaisesRegex(RuntimeError, "build failed"):
                    native_build.build(Path(tmp), "sha256:" + "a" * 64, "1234")
            args = run.call_args.args
            name = args[args.index("--name") + 1]
            self.assertTrue(name.startswith("kryvola-native-"))
            self.assertIn(f"type=bind,src={native_build.ROOT},dst=/src,readonly", args)
            self.assertEqual(args.count("--env"), 1)
            self.assertIn("SOURCE_DATE_EPOCH=1234", args)
            cleanup.assert_called_once_with(
                ["docker", "rm", "--force", name],
                check=False,
                capture_output=True,
            )

    def test_assembly_passes_exact_native_outputs_to_boundary_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp)
            with patch.object(
                m1.release, "run", side_effect=RuntimeError("boundary reached")
            ) as run:
                with self.assertRaisesRegex(RuntimeError, "boundary reached"):
                    m1.assemble("a" * 40, {}, artifacts)
            args = run.call_args.args
            self.assertEqual(
                args[1:],
                (
                    m1.ROOT / "tools/cpu_boundary.py",
                    "--engine",
                    artifacts / "kryvola-cpu-engine",
                    "--evaluator",
                    artifacts / "kryvola-cpu-evaluator",
                ),
            )

    def test_subject_comparison_requires_both_workers_and_one_owner_wheel(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with self.assertRaises(ValueError):
                native_build.subjects(folder)
            for name in (
                "kryvola-cpu-engine",
                "kryvola-cpu-evaluator",
                "kryvola_owner-fixture.whl",
            ):
                (folder / name).write_bytes(b"public fixture")
            self.assertEqual(len(native_build.subjects(folder)), 3)
            (folder / "unexpected").write_bytes(b"public fixture")
            with self.assertRaises(ValueError):
                native_build.subjects(folder)

    def test_invalid_epoch_never_starts_a_container(self):
        with patch.object(native_build, "run") as run:
            for epoch in ("-1", "not-a-time"):
                with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                    native_build.build(Path("unused"), "fixture", epoch)
            run.assert_not_called()
