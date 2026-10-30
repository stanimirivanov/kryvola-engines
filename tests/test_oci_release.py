"""OCI subjects and runtime/archive bindings fail closed without registry writes."""

import copy
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import oci_release as oci

SOURCE = "a" * 40
IMAGE = oci.IMAGE + "@sha256:" + "b" * 64


class OciTests(unittest.TestCase):
    def test_only_exact_fake_digest_references(self):
        self.assertEqual(oci.image_ref(IMAGE), IMAGE)
        for value in (
            None,
            oci.IMAGE + ":latest",
            IMAGE.replace("fake-evaluator", "owner"),
            IMAGE + "extra",
        ):
            with self.assertRaises(ValueError):
                oci.image_ref(value)

    def test_signed_subjects_bind_expected_source_archive_image_and_dockerfile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            package.mkdir()
            oci.release.write(
                package / "manifest.json", {"source": SOURCE, "role": "fake-evaluator"}
            )
            folder = root / "oci"
            folder.mkdir()
            archive = oci.release.sha(package / "manifest.json")
            dockerfile = oci.release.sha(oci.release.ROOT / "containers/Dockerfile")
            oci.release.write(
                folder / "provenance.json", oci.statement(SOURCE, IMAGE, archive, dockerfile)
            )
            oci.release.write(
                folder / "sbom.json", {"spdxVersion": "SPDX-2.3", "packages": ["fixture"]}
            )
            (folder / "manifest.sigstore.json").write_text("fixture only")
            manifest = {
                "format": "fake-oci-v1",
                "source": SOURCE,
                "image": IMAGE,
                "archive_manifest_sha256": archive,
                "dockerfile_sha256": dockerfile,
                "production_ready": False,
                "subjects": {
                    n: oci.release.sha(folder / n) for n in ("sbom.json", "provenance.json")
                },
            }
            oci.release.write(folder / "manifest.json", manifest)
            with (
                patch.object(oci.release, "verify"),
                patch.object(oci.release, "tool", return_value="cosign"),
                patch.object(oci.release, "run") as run,
                patch.object(oci, "runtime"),
            ):
                oci.verify(folder, package, SOURCE, IMAGE)
                self.assertEqual(run.call_args.args[-1], IMAGE)
                self.assertIn("--certificate-github-workflow-sha", run.call_args.args)
                for field, value in (
                    ("image", IMAGE.replace("b", "c")),
                    ("source", "c" * 40),
                    ("archive_manifest_sha256", "0" * 64),
                    ("dockerfile_sha256", "0" * 64),
                    ("production_ready", True),
                ):
                    changed = copy.deepcopy(manifest)
                    changed[field] = value
                    oci.release.write(folder / "manifest.json", changed)
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        oci.verify(folder, package, SOURCE, IMAGE)
                oci.release.write(folder / "manifest.json", manifest)
                run.side_effect = subprocess.CalledProcessError(1, "cosign")
                with self.assertRaises(subprocess.CalledProcessError):
                    oci.verify(folder, package, SOURCE, IMAGE)

    def test_pulled_image_files_reject_owner_injection_and_binary_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            contents = {"engine": b"fixture", "LICENSE": b"license", "Cargo.lock": b"lock"}
            with tarfile.open(package / "package.tar", "w") as archive:
                for name, data in contents.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            for change in (None, "owner.key", "engine"):

                def simulate(*args, change=change, **kwargs):
                    stdout = ""
                    if "inspect" in args:
                        stdout = json.dumps(
                            {"User": "65532:65532", "Entrypoint": ["/opt/kryvola/engine"]}
                        )
                    if "create" in args:
                        stdout = "fixture-container"
                    if "cp" in args:
                        root = args[-1]
                        for name, data in contents.items():
                            (root / name).write_bytes(data)
                        if change:
                            (root / change).write_bytes(b"injected")
                    return subprocess.CompletedProcess(args, 0, stdout=stdout)

                with patch.object(oci.release, "run", side_effect=simulate) as run:
                    if change:
                        with self.assertRaises(ValueError):
                            oci.runtime(IMAGE, package)
                    else:
                        oci.runtime(IMAGE, package)
                    self.assertTrue(
                        any(call.args[:2] == ("docker", "rm") for call in run.call_args_list)
                    )

    def test_registry_auth_failure_is_not_absence(self):
        with (
            patch.object(oci.release, "verify"),
            patch.object(
                oci.release, "read", return_value={"source": SOURCE, "role": "fake-evaluator"}
            ),
            patch.object(
                oci.release,
                "run",
                return_value=subprocess.CompletedProcess([], 1, stderr="unauthorized"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "OCI_ABSENCE_UNCONFIRMED"):
                oci.publish(Path("fixture"), SOURCE)
