"""Real Docker regression; run after cpu_boundary.py builds the worker binaries."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from tools import cpu_engine_package as package
from tools import m1_release


class CpuImageReproductionTests(unittest.TestCase):
    def test_clean_builds_have_equal_actual_configuration_digests(self):
        engine = Path(
            os.environ.get(
                "KRYVOLA_IMAGE_TEST_ENGINE", package.ROOT / "target/debug/kryvola-cpu-engine"
            )
        )
        evaluator = Path(
            os.environ.get(
                "KRYVOLA_IMAGE_TEST_EVALUATOR",
                package.ROOT / "crates/cpu-evaluator/target/release/kryvola-cpu-evaluator",
            )
        )
        epoch = package.run("git", "show", "-s", "--format=%ct", "HEAD")
        images = [f"kryvola-reproduction-test:{uuid.uuid4().hex}" for _ in range(3)]
        digests = []
        try:
            with tempfile.TemporaryDirectory(prefix="cpu-reproduction-negative-") as tmp:
                changed = Path(tmp) / "changed-engine"
                shutil.copyfile(engine, changed)
                with changed.open("ab") as stream:
                    stream.write(b"public reproduction negative control\n")
                for image, binary in zip(images, (engine, engine, changed), strict=True):
                    with (
                        patch.object(package, "IMAGE", image),
                        patch.dict(os.environ, {"SOURCE_DATE_EPOCH": epoch}),
                        patch.object(
                            sys, "argv", ["cpu_engine_package.py", str(binary), str(evaluator)]
                        ),
                    ):
                        package.main()
                    digests.append(m1_release.image_identity(image))
            self.assertEqual(digests[0], digests[1], "IMAGE_NON_REPRODUCIBLE")
            self.assertNotEqual(digests[0], digests[2], "changed worker bytes must change identity")
            print(f"CPU_IMAGE_REPRODUCIBLE config_sha256={digests[0]}")
        finally:
            for image in images:
                subprocess.run(
                    ["docker", "image", "rm", "--force", image],
                    cwd=package.ROOT,
                    check=False,
                    stdout=subprocess.DEVNULL,
                )


if __name__ == "__main__":
    unittest.main()
