"""Offline negative controls; real tools and two-build comparisons run on CI."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "engine"
        self.binary.write_bytes(b"unit-fixture-not-native")
        self.output = self.root / "package"

    def simulate(self, *args, **kwargs):
        if "scan" in args:
            release.write(
                self.output / "sbom.json",
                {"spdxVersion": "SPDX-2.3", "packages": [{"name": "unit-fixture"}]},
            )
        stdout = ""
        if args[:3] == ("git", "rev-parse", "HEAD"):
            stdout = "a" * 40
        if "--artifact-role" in args:
            stdout = "fake-evaluator"
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    def package(self):
        release.package("fake-evaluator", self.binary, self.binary, self.output)
        (self.output / "manifest.sigstore.json").write_text("unit-test-only")

    def test_subjects_sbom_and_role_boundaries(self):
        with (
            patch.object(release, "tool", side_effect=lambda name: name),
            patch.object(release, "run", side_effect=self.simulate),
        ):
            self.package()
            release.verify(self.output, Path("trusted-key.pub"))
            for filename in ("package.tar", "sbom.json", "provenance.json"):
                path = self.output / filename
                original = path.read_bytes()
                path.write_bytes(original + b"tamper")
                with self.subTest(filename=filename), self.assertRaises(ValueError):
                    release.verify(self.output, Path("trusted-key.pub"))
                path.write_bytes(original)
            extra = self.output / "owner.key"
            extra.write_text("not-a-real-key")
            with self.assertRaisesRegex(ValueError, "UNEXPECTED_PACKAGE_CONTENT"):
                release.verify(self.output)
            extra.unlink()
            (self.output / "sbom.json").unlink()
            with self.assertRaises(ValueError):
                release.verify(self.output)

    def test_identity_is_pinned_and_keyed_publication_forbidden(self):
        with (
            patch.object(release, "tool", side_effect=lambda name: name),
            patch.object(release, "run", side_effect=self.simulate) as call,
        ):
            self.package()
            release.verify(self.output, publish=True)
            args = call.call_args.args
            self.assertIn(release.IDENTITY, args)
            self.assertIn(release.ISSUER, args)
            self.assertNotIn("--insecure-ignore-tlog", args)
            with self.assertRaisesRegex(ValueError, "KEYED_PUBLICATION_FORBIDDEN"):
                release.verify(self.output, Path("self-selected.pub"), publish=True)
            manifest = release.read(self.output / "manifest.json")
            manifest["source"] = "b" * 40
            release.write(self.output / "manifest.json", manifest)
            with self.assertRaisesRegex(ValueError, "PUBLICATION_SOURCE_MISMATCH"):
                release.verify(self.output, publish=True)

    def test_distribution_denials_and_nonreproducible_inputs(self):
        for role in ("cpu-evaluator", "owner-fixture", "local-prover"):
            self.assertEqual(release.disposition(role), "DENY")
            with self.subTest(role=role), self.assertRaises(ValueError):
                release.disposition(role, publish=True)
        other = self.root / "different"
        other.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "NON_REPRODUCIBLE_BINARY"):
            release.package("fake-evaluator", self.binary, other, self.output)

    def test_owner_binary_cannot_be_packaged_as_compute(self):
        with patch.object(
            release, "run", return_value=subprocess.CompletedProcess([], 0, stdout="owner-fixture")
        ):
            with self.assertRaisesRegex(ValueError, "WRONG_BINARY_ROLE"):
                release.package("cpu-evaluator", self.binary, self.binary, self.output)

    def test_tool_digest_and_duplicate_metadata_rejection(self):
        with patch.object(release, "TOOLS", self.root):
            (self.root / "cosign").write_bytes(b"untrusted")
            with self.assertRaisesRegex(ValueError, "TOOL_INTEGRITY"):
                release.tool("cosign")
        path = self.root / "duplicate.json"
        path.write_text('{"role":1,"role":2}')
        with self.assertRaises(ValueError):
            release.read(path)

    def test_archive_bytes_are_deterministic(self):
        with (
            patch.object(release, "tool", side_effect=lambda name: name),
            patch.object(release, "run", side_effect=self.simulate),
        ):
            self.package()
            first = release.sha(self.output / "package.tar")
            self.output = self.root / "second-package"
            self.package()
            self.assertEqual(first, release.sha(self.output / "package.tar"))

    def test_fake_label_cannot_publish_crypto_dependencies(self):
        (self.root / "LICENSE").write_text("unit-fixture")
        (self.root / "Cargo.lock").write_text('[[package]]\nname="tfhe"\nversion="1.8.1"\n')
        with (
            patch.object(release, "ROOT", self.root),
            patch.object(release, "tool", side_effect=lambda name: name),
            patch.object(release, "run", side_effect=self.simulate),
        ):
            self.package()
            with self.assertRaisesRegex(ValueError, "DISTRIBUTION_DENIED_LOCK"):
                release.verify(self.output, publish=True)
