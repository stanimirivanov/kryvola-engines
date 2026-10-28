"""Offline candidate, use-class and representative Cargo-consumer negative controls."""

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.dependency_policy import ROOT, PolicyError, admit, validate


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "config", self.root / "config")
        for name in ("rust-toolchain.toml", "pyproject.toml", ".python-version"):
            shutil.copyfile(ROOT / name, self.root / name)
        (self.root / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
        self.path = self.root / "config/dependency-policy.json"
        self.policy = json.loads(self.path.read_bytes())

    def write(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")

    def test_real_policy_and_isolated_research_candidate_pass(self):
        validate(ROOT)
        policy = validate(self.root)
        self.assertEqual(admit(policy, "tfhe", "local_research")["version"], "1.8.1")
        for purpose in ("artifact_distribution", "commercial_service", "unknown"):
            with self.assertRaisesRegex(PolicyError, "UNAUTHORIZED_USE"):
                admit(policy, "tfhe", purpose)
        with self.assertRaises(PolicyError):
            admit(policy, "openfhe", "local_research")

    def test_missing_pins_unapproved_features_and_false_qualification_fail(self):
        for mutate in (
            lambda p: p["candidates"][0].pop("version"),
            lambda p: p["candidates"][0].update(version="latest"),
            lambda p: p["candidates"][0]["artifact"].update(sha256=""),
            lambda p: p["candidates"][0].update(source_revision="main"),
            lambda p: p["candidates"][0].update(license="MIT"),
            lambda p: p["candidates"][0].update(default_features=True),
            lambda p: p["candidates"][1].update(features=["network"]),
            lambda p: p["candidates"][0]["compatibility"].update(status="VERIFIED"),
            lambda p: p["candidates"][0]["permissions"].update(artifact_distribution="ALLOW"),
            lambda p: p["candidates"][0].update(legal_review="APPROVED"),
            lambda p: p["optional"]["redpanda"].update(disposition="APPROVED"),
            lambda p: p["toolchain"].update(rust="1.0.0"),
        ):
            policy = json.loads(json.dumps(self.policy))
            mutate(policy)
            self.write(policy)
            with self.subTest(mutate=mutate), self.assertRaises(PolicyError):
                validate(self.root)

    def test_tampered_and_escaping_evidence_fail(self):
        pin = self.policy["candidates"][0]
        path = self.root / pin["evidence"]["Cargo.toml"]["path"]
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with self.assertRaisesRegex(PolicyError, "EVIDENCE_MISMATCH"):
            validate(self.root)
        path.write_bytes(original)
        pin["evidence"]["Cargo.toml"]["path"] = "../outside"
        self.write(self.policy)
        with self.assertRaisesRegex(PolicyError, "UNSAFE_EVIDENCE"):
            validate(self.root)

    def test_exact_direct_dependency_passes_but_floating_gpu_and_patches_fail(self):
        manifest = self.root / "Cargo.toml"
        baseline = manifest.read_text()
        exact = (
            'tfhe={version="=1.8.1",default-features=false,features=["integer","software-prng"]}'
        )
        manifest.write_text(baseline + "[dependencies]\n" + exact + "\n")
        validate(self.root)
        for declaration in (
            'tfhe="1.8.1"',
            exact.replace("=1.8.1", "1.8.1"),
            exact.replace('"integer"', '"gpu"'),
            'alias={package="tfhe",git="https://github.com/zama-ai/tfhe-rs"}',
            'tfhe-cuda-backend="=0.16.0"',
        ):
            manifest.write_text(baseline + "[dependencies]\n" + declaration + "\n")
            with self.subTest(declaration=declaration), self.assertRaises(PolicyError):
                validate(self.root)
        manifest.write_text(baseline + '[patch.crates-io]\ntfhe={path="../unreviewed"}\n')
        with self.assertRaisesRegex(PolicyError, "UNPINNED_CONSUMER"):
            validate(self.root)
        manifest.write_text(
            baseline + "[dependencies]\n" + exact + '\n[features]\nfast=["tfhe/gpu"]\n'
        )
        with self.assertRaisesRegex(PolicyError, "UNAPPROVED_FEATURES"):
            validate(self.root)

    def test_changed_lockfile_identity_fails(self):
        (self.root / "Cargo.lock").write_text(
            '[[package]]\nname="tfhe"\nversion="1.8.1"\n'
            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum="' + "0" * 64 + '"\n'
        )
        with self.assertRaisesRegex(PolicyError, "UNPINNED_CONSUMER"):
            validate(self.root)

    def test_cli_denies_distribution_and_altered_artifact(self):
        artifact = self.root / "changed.crate"
        artifact.write_bytes(b"wrong")
        for extra in (
            ["--purpose", "artifact_distribution"],
            ["--purpose", "local_research", "--artifact", str(artifact)],
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/dependency_policy.py"),
                    "--root",
                    str(self.root),
                    "--candidate",
                    "tfhe",
                    *extra,
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.strip(), "dependency-policy: REJECTED")
