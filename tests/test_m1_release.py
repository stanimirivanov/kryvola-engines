"""M1 candidate integrity and explicit development distribution approval."""

import copy
import tempfile
import unittest
from pathlib import Path

from tools import m1_release as m1
from tools import release

SOURCE = "a" * 40


def candidate(folder):
    contents = {name: b"public fixture" for name in m1.CPU_FILES}
    m1.archive(folder / "cpu-runtime.tar", contents)
    (folder / "kryvola_owner-0.1.0.dev2-cp314-cp314-linux_x86_64.whl").write_bytes(b"owner fixture")
    for name, source in m1.INPUTS.items():
        (folder / name).write_bytes((m1.ROOT / source).read_bytes())
    (folder / "sbom.json").write_bytes(b"{}")
    release.write(
        folder / "image-subject.json",
        {
            "source": SOURCE,
            "cpu_sha256": m1.sha(folder / "cpu-runtime.tar"),
            "config_sha256": "0" * 64,
        },
    )
    return m1.seal(folder, SOURCE, "CANDIDATE")


class M1ReleaseTests(unittest.TestCase):
    def test_candidate_is_denied_for_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            manifest = candidate(folder)
            self.assertEqual(m1.validate(folder, SOURCE), manifest)
            self.assertEqual(manifest["distribution"], "DENY")
            with self.assertRaises(ValueError):
                m1.validate(folder, SOURCE, approved=True)
            with self.assertRaises((ValueError, OSError)):
                m1.permissions(folder, SOURCE)

    def test_missing_tampered_or_owner_injected_artifact_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            manifest = candidate(folder)
            for name in manifest["subjects"]:
                path = folder / name
                original = path.read_bytes()
                path.write_bytes(original + b"tampered")
                with self.assertRaises(ValueError):
                    m1.validate(folder, SOURCE)
                path.unlink()
                with self.assertRaises(ValueError):
                    m1.validate(folder, SOURCE)
                path.write_bytes(original)
            m1.archive(
                folder / "cpu-runtime.tar",
                {**{name: b"fixture" for name in m1.CPU_FILES}, "owner.key": b"fixture"},
            )
            m1.seal(folder, SOURCE, "CANDIDATE")
            with self.assertRaises(ValueError):
                m1.validate(folder, SOURCE)

    def test_changed_source_schema_and_distribution_do_not_admit(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            manifest = candidate(folder)
            for field, value in (("source", "b" * 40), ("spec", {}), ("distribution", "APPROVED")):
                changed = copy.deepcopy(manifest)
                changed[field] = value
                release.write(folder / "manifest.json", changed)
                with self.assertRaises(ValueError):
                    m1.validate(folder, SOURCE)


class PermissionTests(unittest.TestCase):
    def test_denied_publish_has_no_registry_side_effect(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            candidate(folder)
            with patch.object(m1.release, "run") as run:
                with self.assertRaises(ValueError):
                    m1.publish(
                        folder,
                        SOURCE,
                        m1.sha(folder / "cpu-runtime.tar"),
                        m1.sha(m1.wheel(folder)),
                        "0" * 64,
                    )
                run.assert_not_called()


class StagingTests(unittest.TestCase):
    def test_published_image_stages_executable_cpu_files(self):
        import os
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "candidate"
            folder.mkdir()
            candidate(folder)
            # Use real runner/licence bytes; they are independently checked before image build.
            contents = {name: b"fixture" for name in m1.CPU_FILES}
            contents.update(
                {
                    "cpu_runner.py": (m1.ROOT / "tools/cpu_runner.py").read_bytes(),
                    "LICENSE": (m1.ROOT / "LICENSE").read_bytes(),
                }
            )
            m1.archive(folder / "cpu-runtime.tar", contents)
            release.write(
                folder / "image-subject.json",
                {
                    "source": SOURCE,
                    "cpu_sha256": m1.sha(folder / "cpu-runtime.tar"),
                    "config_sha256": "0" * 64,
                },
            )
            m1.seal(folder, SOURCE, "CANDIDATE")

            def boundary(*args, **kwargs):
                if args[0] == "git":
                    from types import SimpleNamespace

                    return SimpleNamespace(stdout="0")
                self.assertTrue(os.access(args[-1], os.X_OK))
                self.assertTrue(os.access(args[-2], os.X_OK))
                raise RuntimeError("image build reached")

            from tests.test_m1_owner_approval import CONTEXT
            from tests.test_m1_owner_approval import approve as owner_approve

            with patch.dict(os.environ, CONTEXT, clear=True):
                approval = owner_approve(folder)

            def approve(*args):
                # A caller-side change after authorization must not change staged bytes.
                (folder / "cpu-runtime.tar").write_bytes(b"changed after verification")
                return approval

            with (
                patch.dict(os.environ, CONTEXT, clear=True),
                patch.object(m1, "permissions", side_effect=approve),
                patch.object(m1.release, "run", side_effect=boundary),
            ):
                with self.assertRaisesRegex(RuntimeError, "image build reached"):
                    m1.publish(
                        folder,
                        SOURCE,
                        m1.sha(folder / "cpu-runtime.tar"),
                        m1.sha(m1.wheel(folder)),
                        "0" * 64,
                    )


class ImageReproductionTests(unittest.TestCase):
    def test_image_context_uses_fixed_modes_and_timestamps(self):
        from tools import cpu_engine_package

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in cpu_engine_package.FILES:
                (root / name).write_bytes(b"fixture")
                (root / name).chmod(0o777)
            cpu_engine_package.normalize(root, 1234)
            for name in cpu_engine_package.FILES:
                self.assertEqual((root / name).stat().st_mtime_ns, 1234 * 10**9)
                self.assertEqual(
                    (root / name).stat().st_mode & 0o777,
                    0o755 if name.startswith("kryvola-cpu-") else 0o644,
                )
