"""Single-owner development approval is explicit, exact and never specialist review."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_m1_release import SOURCE, candidate
from tools import m1_release as m1
from tools import release

CONTEXT = {
    "GITHUB_ACTOR": "stanimirivanov",
    "GITHUB_REPOSITORY": "stanimirivanov/kryvola-engines",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_SHA": SOURCE,
    "GITHUB_RUN_ID": "123",
    "GITHUB_WORKFLOW_REF": m1.IDENTITY.removeprefix("https://github.com/"),
}


def approve(folder):
    return m1.authorize(
        folder,
        SOURCE,
        m1.sha(folder / "cpu-runtime.tar"),
        m1.sha(m1.wheel(folder)),
        "0" * 64,
        approve=True,
    )


class OwnerApprovalTests(unittest.TestCase):
    def test_one_owner_approval_binds_all_subjects_without_specialist_keys(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, CONTEXT, clear=True),
        ):
            folder = Path(temporary)
            candidate(folder)
            before = (folder / "manifest.json").read_bytes()
            result = approve(folder)
            self.assertEqual(result["owner"], "stanimirivanov")
            self.assertEqual(result["intended_use"], "development_distribution")
            self.assertFalse(result["independent_review"])
            self.assertFalse(result["production_ready"])
            self.assertEqual(m1.permissions(folder, SOURCE), result)
            self.assertEqual((folder / "manifest.json").read_bytes(), before)
            self.assertEqual(m1.validate(folder, SOURCE)["state"], "CANDIDATE")

    def test_missing_checkbox_or_wrong_actor_context_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            candidate(folder)
            with patch.dict(os.environ, CONTEXT, clear=True), self.assertRaises(ValueError):
                m1.authorize(
                    folder,
                    SOURCE,
                    m1.sha(folder / "cpu-runtime.tar"),
                    m1.sha(m1.wheel(folder)),
                    "0" * 64,
                )
            for key, value in (
                ("GITHUB_ACTOR", "another-writer"),
                ("GITHUB_REF", "refs/heads/feature"),
                ("GITHUB_EVENT_NAME", "push"),
                ("GITHUB_SHA", "b" * 40),
                ("GITHUB_REPOSITORY", "attacker/kryvola-engines"),
                ("GITHUB_WORKFLOW_REF", "another-workflow"),
                ("GITHUB_RUN_ID", ""),
            ):
                with (
                    self.subTest(key=key),
                    patch.dict(os.environ, CONTEXT | {key: value}, clear=True),
                ):
                    with self.assertRaises(ValueError):
                        approve(folder)
                    self.assertFalse((folder / "owner-approval.json").exists())

    def test_changed_expected_hash_or_approval_subject_is_rejected(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, CONTEXT, clear=True),
        ):
            folder = Path(temporary)
            candidate(folder)
            with self.assertRaisesRegex(ValueError, "CANDIDATE_PIN"):
                m1.authorize(
                    folder, SOURCE, "f" * 64, m1.sha(m1.wheel(folder)), "0" * 64, approve=True
                )
            approval = approve(folder)
            for field, value in (
                ("owner", "other"),
                ("source", "b" * 40),
                ("cpu_sha256", "f" * 64),
                ("owner_sha256", "f" * 64),
                ("image_sha256", "f" * 64),
                ("independent_review", True),
                ("production_ready", True),
                ("run_id", ""),
                ("intended_use", "commercial_service"),
                ("extra", "value"),
            ):
                with self.subTest(field=field):
                    release.write(folder / "owner-approval.json", approval | {field: value})
                    with self.assertRaises(ValueError):
                        m1.permissions(folder, SOURCE)
            (folder / "owner-approval.json").unlink()
            with self.assertRaises((ValueError, OSError)):
                m1.permissions(folder, SOURCE)

    def test_development_profile_is_versioned_and_manifest_binds_owner_approval(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, CONTEXT, clear=True),
        ):
            folder = Path(temporary)
            candidate(folder)
            approve(folder)
            release.write(
                folder / "image.json",
                {
                    "source": SOURCE,
                    "image": m1.IMAGE + "@sha256:" + "1" * 64,
                    "cpu_sha256": m1.sha(folder / "cpu-runtime.tar"),
                },
            )
            manifest = m1.seal(folder, SOURCE, "APPROVED")
            self.assertEqual(manifest["schema_version"], "engines-m1-v2")
            self.assertEqual(manifest["distribution"], "OWNER_APPROVED_DEVELOPMENT_ONLY")
            self.assertIn("owner-approval.json", manifest["subjects"])
            self.assertNotIn("permission-evidence.tar", manifest["subjects"])
            m1.validate(folder, SOURCE, approved=True)
            approval = json.loads((folder / "owner-approval.json").read_bytes())
            release.write(folder / "owner-approval.json", approval | {"owner": "other"})
            with self.assertRaises(ValueError):
                m1.validate(folder, SOURCE, approved=True)

    def test_wrong_run_and_invalid_publisher_signature_fail_before_registry_effects(self):
        import subprocess

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, CONTEXT, clear=True),
        ):
            folder = Path(temporary)
            candidate(folder)
            approve(folder)
            pins = (
                folder,
                SOURCE,
                m1.sha(folder / "cpu-runtime.tar"),
                m1.sha(m1.wheel(folder)),
                "0" * 64,
            )
            with (
                patch.dict(os.environ, {"GITHUB_RUN_ID": "124"}),
                patch.object(m1.release, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "OWNER_RUN_MISMATCH"):
                    m1.publish(*pins)
                run.assert_not_called()
            release.write(
                folder / "image.json",
                {
                    "source": SOURCE,
                    "image": m1.IMAGE + "@sha256:" + "1" * 64,
                    "cpu_sha256": pins[2],
                },
            )
            m1.seal(folder, SOURCE, "APPROVED")
            with (
                patch.object(m1.release, "tool", return_value=Path("cosign")),
                patch.object(
                    m1.release, "run", side_effect=subprocess.CalledProcessError(1, "cosign")
                ) as run,
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    m1.verify(folder, SOURCE)
                self.assertEqual(run.call_count, 1)
                command = run.call_args.args
                self.assertIn("--certificate-identity", command)
                self.assertIn("--certificate-oidc-issuer", command)
                self.assertIn("--certificate-github-workflow-sha", command)
                self.assertIn(SOURCE, command)
                self.assertIn("workflow_dispatch", command)
                self.assertNotIn("--key", command)
