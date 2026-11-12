"""Reproducible builds must not silently use the host's integrated exporter."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import cpu_engine_package as package


class CpuImageBuilderTests(unittest.TestCase):
    def test_explicit_pinned_builder_with_no_cache_and_cleanup_even_on_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as tmp:
                context = Path(tmp)
                for name in package.FILES:
                    (context / name).write_bytes(b"public fixture")
                commands = []

                def docker(*args, commands=commands, fail=fail):
                    commands.append(args)
                    if fail and args[:3] == ("docker", "buildx", "build"):
                        raise subprocess.CalledProcessError(1, args)
                    return ""

                with patch.object(package, "run", side_effect=docker):
                    if fail:
                        with self.assertRaises(subprocess.CalledProcessError):
                            package.build_image(context, "1234")
                    else:
                        package.build_image(context, "1234")
                create, build, remove = commands
                self.assertEqual(create[:4], ("docker", "buildx", "create", "--name"))
                builder = create[4]
                self.assertEqual(
                    create[5:],
                    ("--driver", "docker-container", "--driver-opt", f"image={package.BUILDKIT}"),
                )
                self.assertRegex(package.BUILDKIT, r"^moby/buildkit:v[\d.]+@sha256:[0-9a-f]{64}$")
                self.assertEqual(
                    build[:14],
                    (
                        "docker",
                        "buildx",
                        "build",
                        "--builder",
                        builder,
                        "--platform",
                        "linux/amd64",
                        "--no-cache",
                        "--provenance=false",
                        "--output",
                        "type=docker,rewrite-timestamp=true",
                        "--build-arg",
                        "SOURCE_DATE_EPOCH=1234",
                        "--file",
                    ),
                )
                self.assertEqual(remove, ("docker", "buildx", "rm", builder))
                self.assertEqual((context / "LICENSE").stat().st_mtime_ns, 1234 * 10**9)

    def test_invalid_epoch_fails_before_starting_any_builder(self):
        with patch.object(package, "run") as docker:
            for epoch in ("-1", "not-an-epoch"):
                with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                    package.build_image(Path("unused"), epoch)
            docker.assert_not_called()
