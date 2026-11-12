"""Configuration identity comes from image bytes, never a Docker image/manifest ID."""

import hashlib
import io
import json
import subprocess
import tarfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import m1_release as m1

CONFIG = json.dumps(
    {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "c" * 64]},
    }
).encode()
DIGEST = hashlib.sha256(CONFIG).hexdigest()
IMAGE_ID = "sha256:" + "f" * 64


def exported_identity(
    layout="oci",
    *,
    data=CONFIG,
    reference=None,
    manifests=1,
    missing=False,
    duplicate=False,
    symlink=False,
    save_error=False,
):
    name = reference or (
        "blobs/sha256/" + hashlib.sha256(data).hexdigest()
        if layout == "oci"
        else hashlib.sha256(data).hexdigest() + ".json"
    )

    def docker(*args, **kwargs):
        if args[:3] == ("docker", "image", "inspect"):
            return SimpleNamespace(stdout=IMAGE_ID + "\n")
        if args[:3] == ("docker", "image", "save"):
            if save_error:
                raise subprocess.CalledProcessError(1, args)
            assert args[-1] == IMAGE_ID
            output = Path(args[args.index("--output") + 1])
            records = [{"Config": name, "RepoTags": None, "Layers": []}] * manifests
            with tarfile.open(output, "w") as archive:
                entries = [("manifest.json", json.dumps(records).encode())]
                if not missing:
                    entries += [(name, data)] * (2 if duplicate else 1)
                for filename, raw in entries:
                    item = tarfile.TarInfo(filename)
                    item.size = len(raw)
                    if symlink and filename == name:
                        item.type, item.linkname, item.size = tarfile.SYMTYPE, "outside", 0
                    archive.addfile(item, io.BytesIO(raw))
            return SimpleNamespace(returncode=0)
        raise AssertionError(args)

    with patch.object(m1.release, "run", side_effect=docker):
        return m1.image_identity("worker:local")


class ImageIdentityTests(unittest.TestCase):
    def test_containerd_manifest_id_is_not_the_configuration_digest(self):
        self.assertNotEqual(IMAGE_ID.removeprefix("sha256:"), DIGEST)
        self.assertEqual(exported_identity(), DIGEST)

    def test_classic_docker_save_configuration(self):
        self.assertEqual(exported_identity("classic"), DIGEST)

    def test_unsafe_ambiguous_missing_and_tampered_configs_are_rejected(self):
        cases = [
            dict(reference="../config.json"),
            dict(manifests=0),
            dict(manifests=2),
            dict(missing=True),
            dict(duplicate=True),
            dict(symlink=True),
            dict(reference="blobs/sha256/" + "a" * 64),
            dict(data=b"not json"),
            dict(data=b'{"schemaVersion":2,"config":{}}'),
            dict(data=CONFIG[:-1] + b',"padding":"' + b"x" * (1 << 20) + b'"}'),
        ]
        for case in cases:
            with self.subTest(
                case={k: (len(v) if isinstance(v, bytes) else v) for k, v in case.items()}
            ):
                with self.assertRaises(ValueError):
                    exported_identity(**case)

    def test_export_failure_never_falls_back_to_image_id(self):
        with self.assertRaises(subprocess.CalledProcessError):
            exported_identity(save_error=True)

    def test_tag_uses_immutable_docker_reference_not_configuration_digest(self):
        import os
        import tempfile

        from tests.test_m1_owner_approval import CONTEXT
        from tests.test_m1_release import SOURCE, candidate

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, CONTEXT, clear=True),
        ):
            folder = Path(temporary)
            candidate(folder)
            contents = {name: b"public fixture" for name in m1.CPU_FILES}
            for name in ("cpu_runner.py", "LICENSE"):
                contents[name] = (
                    m1.ROOT / ("tools/cpu_runner.py" if name == "cpu_runner.py" else name)
                ).read_bytes()
            m1.archive(folder / "cpu-runtime.tar", contents)
            m1.release.write(
                folder / "image-subject.json",
                {
                    "source": SOURCE,
                    "cpu_sha256": m1.sha(folder / "cpu-runtime.tar"),
                    "config_sha256": DIGEST,
                },
            )
            m1.seal(folder, SOURCE, "CANDIDATE")
            pins = (
                folder,
                SOURCE,
                m1.sha(folder / "cpu-runtime.tar"),
                m1.sha(m1.wheel(folder)),
                DIGEST,
            )
            m1.authorize(*pins, approve=True)

            def docker(*args, **kwargs):
                if args[0] == "git":
                    return SimpleNamespace(stdout="0")
                if args[:3] == ("docker", "manifest", "inspect"):
                    return SimpleNamespace(returncode=1, stderr=b"no such manifest")
                if args[:2] == ("docker", "tag"):
                    self.assertEqual(args[2], IMAGE_ID)
                    self.assertNotEqual(args[2], "sha256:" + DIGEST)
                    raise RuntimeError("tag reference checked")
                if args[0] == "docker":
                    self.fail(f"Unexpected registry operation: {args[:2]}")
                return SimpleNamespace(returncode=0)

            with (
                patch.object(m1, "image_reference", return_value=IMAGE_ID),
                patch.object(m1, "image_identity", return_value=DIGEST) as identity,
                patch.object(m1, "image_check"),
                patch.object(m1.release, "run", side_effect=docker),
            ):
                with self.assertRaisesRegex(RuntimeError, "tag reference checked"):
                    m1.publish(*pins)
                identity.assert_called_once_with(IMAGE_ID)
