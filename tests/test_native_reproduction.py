"""Real compiler checks for source and Cargo registry path normalization."""

import hashlib
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def compile_fixture(root: Path, environment) -> tuple[str, str]:
    repo = root / "source"
    cargo_home = root / "cargo-home"
    output = root / "output"
    dependency = cargo_home / "registry/src/public-path-fixture-1.0.0/lib.rs"
    dependency.parent.mkdir(parents=True, exist_ok=True)
    repo.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    dependency.write_text("pub fn source() -> &'static str { file!() }\n")
    (output / "generated.rs").write_text("pub fn source() -> &'static str { file!() }\n")
    source = repo / "main.rs"
    source.write_text(
        'mod generated { include!(concat!(env!("OUT_DIR"), "/generated.rs")); }\n'
        'fn main() { println!("{} {} {}", file!(), '
        "path_fixture::source(), generated::source()); }\n"
    )
    env = environment(repo, cargo_home, output) | {"OUT_DIR": str(output)}
    flags = (
        env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        if env.get("CARGO_ENCODED_RUSTFLAGS")
        else shlex.split(env.get("RUSTFLAGS", ""))
    )
    compiler = subprocess.check_output(
        ["rustup", "which", "rustc", "--toolchain", "1.98.1"], text=True
    ).strip()
    library = output / "libpath_fixture.rlib"
    binary = output / "program"
    for args in (
        [
            "--crate-name",
            "path_fixture",
            "--crate-type",
            "rlib",
            str(dependency),
            "-o",
            str(library),
        ],
        [
            "--crate-name",
            "public_fixture",
            str(source),
            "--extern",
            f"path_fixture={library}",
            "-o",
            str(binary),
        ],
    ):
        subprocess.run(
            [compiler, "--edition=2024", "-C", "opt-level=1", *flags, *args],
            env=env,
            check=True,
            capture_output=True,
            timeout=30,
        )
    return (
        hashlib.sha256(binary.read_bytes()).hexdigest(),
        subprocess.check_output([str(binary)], text=True).strip(),
    )


class NativeReproductionTests(unittest.TestCase):
    def test_native_bytes_do_not_depend_on_checkout_or_registry_location(self):
        from tools.native_build import environment

        with tempfile.TemporaryDirectory(prefix="native-path-reproduction-") as tmp:
            root = Path(tmp)
            original = {
                key: value
                for key, value in os.environ.items()
                if key not in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}
            }
            unnormalized = [
                compile_fixture(root / name, lambda *_, original=original: original)
                for name in ("local", "hosted")
            ]
            self.assertNotEqual(unnormalized[0][0], unnormalized[1][0])
            normalized = [compile_fixture(root / name, environment) for name in ("local", "hosted")]
            self.assertEqual(
                normalized[0][0], normalized[1][0], "NATIVE_SOURCE_PATH_NON_REPRODUCIBLE"
            )
            self.assertEqual(
                normalized[0][1],
                "/src/main.rs /cargo/registry/src/public-path-fixture-1.0.0/lib.rs "
                "/target/generated.rs",
            )

    def test_inherited_codegen_flags_cannot_override_the_release_environment(self):
        from tools.native_build import environment

        with (
            tempfile.TemporaryDirectory(prefix="native-environment-") as tmp,
            patch.dict(
                os.environ,
                {
                    "RUSTFLAGS": "--cfg untrusted_codegen -C target-cpu=native",
                    "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1funtrusted_encoded_codegen",
                    "CARGO_HOME": "/untrusted-cargo",
                    "CARGO_TARGET_DIR": "/untrusted-target",
                },
            ),
        ):
            root = Path(tmp)
            repo, cargo_home, output = (root / name for name in ("repo", "cargo", "target"))
            env = environment(repo, cargo_home, output)
            self.assertEqual(env["CARGO_HOME"], str(cargo_home))
            self.assertEqual(env["CARGO_TARGET_DIR"], str(output))
            self.assertNotIn("untrusted", env.get("RUSTFLAGS", ""))
            self.assertNotIn("untrusted", env.get("CARGO_ENCODED_RUSTFLAGS", ""))
            self.assertNotIn("target-cpu=native", env.get("RUSTFLAGS", ""))
            self.assertNotIn("target-cpu=native", env.get("CARGO_ENCODED_RUSTFLAGS", ""))
