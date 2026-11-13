"""M1-only native toolchain isolation; builds local subjects, never publishes."""

import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "containers/Native-Build.Dockerfile"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=3600, **kwargs)


def environment(repo: Path, cargo_home: Path, output: Path) -> dict[str, str]:
    flags = [
        f"--remap-path-prefix={repo}=/src",
        f"--remap-path-prefix={cargo_home}=/cargo",
        f"--remap-path-prefix={output}=/target",
        "-Ctarget-cpu=x86-64",
    ]
    return os.environ | {
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(output),
        "RUSTFLAGS": "",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
        "CARGO_INCREMENTAL": "0",
        "CARGO_BUILD_JOBS": "2",
        "RAYON_NUM_THREADS": "2",
    }


def inside(evaluator_only=False):
    out = Path("/build/out")
    out.mkdir(exist_ok=True)
    components = (
        ("engine", ["-p", "kryvola-cpu-engine"], "kryvola-cpu-engine"),
        (
            "evaluator",
            ["--manifest-path", "crates/cpu-evaluator/Cargo.toml"],
            "kryvola-cpu-evaluator",
        ),
    )
    for role, args, name in components:
        if evaluator_only and role != "evaluator":
            continue
        target = Path("/build") / ("target-" + role)
        env = environment(ROOT, Path("/build/cargo"), target)
        run("cargo", "build", "--release", "--locked", *args, env=env)
        shutil.copyfile(target / "release" / name, out / name)
        (out / name).chmod(0o755)
    if not evaluator_only:
        run(
            "maturin",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "crates/owner-crypto/python/Cargo.toml",
            "--interpreter",
            "/usr/local/bin/python3",
            "--out",
            out,
            env=environment(ROOT, Path("/build/cargo"), Path("/build/target-owner")),
        )
        if __package__:
            from . import owner_wheel
        else:
            import owner_wheel

        with tempfile.TemporaryDirectory(dir="/build", prefix="installed-owner-") as tmp:
            (wheel,) = out.glob("*.whl")
            owner_wheel.install_and_test(wheel, Path(tmp))


def image():
    tag = "kryvola-native-build:" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="m1-native-context-") as tmp:
        context = Path(tmp)
        for name in ("pyproject.toml", "uv.lock", ".python-version"):
            shutil.copyfile(ROOT / name, context / name)
        shutil.copyfile(RECIPE, context / "Dockerfile")
        try:
            run("docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", tag, context)
            reference = subprocess.check_output(
                ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                text=True,
            ).strip()
        except BaseException:
            subprocess.run(["docker", "image", "rm", "--force", tag], check=False)
            raise
    return tag, reference


def build(output: Path, reference: str, epoch: str, *, changed_source: Path | None = None):
    if not epoch.isdecimal():
        raise ValueError("INVALID_NATIVE_EPOCH")
    output.mkdir(exist_ok=True)
    container = "kryvola-native-" + uuid.uuid4().hex
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        container,
        "--platform",
        "linux/amd64",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={ROOT},dst=/src,readonly",
        "--mount",
        f"type=bind,src={output.resolve()},dst=/build",
        "--env",
        f"SOURCE_DATE_EPOCH={epoch}",
    ]
    if changed_source is not None:
        args += [
            "--mount",
            f"type=bind,src={changed_source},dst=/src/crates/cpu-evaluator/src/main.rs,readonly",
        ]
    try:
        run(*args, reference, *(["--evaluator-only"] if changed_source is not None else []))
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container],
            check=False,
            capture_output=True,
        )
    return output / "out"


def subjects(folder):
    names = {p.name for p in folder.iterdir()}
    wheels = list(folder.glob("kryvola_owner-*.whl"))
    if len(wheels) != 1 or names != {"kryvola-cpu-engine", "kryvola-cpu-evaluator", wheels[0].name}:
        raise ValueError("NATIVE_SUBJECT_INVENTORY")
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir()}


@contextmanager
def artifacts(epoch):
    tag, reference = image()
    try:
        with tempfile.TemporaryDirectory(prefix="m1-native-subjects-") as tmp:
            yield build(Path(tmp), reference, epoch)
    finally:
        run("docker", "image", "rm", tag)


def qualify():
    epoch = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", "HEAD"], text=True
    ).strip()
    tag, reference = image()
    try:
        with tempfile.TemporaryDirectory(prefix="m1-native-reproduction-") as tmp:
            root = Path(tmp)
            first = root / "local"
            expected = subjects(build(first, reference, epoch))
            # Discard all compiler/registry caches before the relocated second build.
            shutil.rmtree(first)
            second = root / "hosted"
            actual = subjects(build(second, reference, epoch))
            if expected != actual:
                raise ValueError("NATIVE_SUBJECTS_NON_REPRODUCIBLE")
            source = ROOT / "crates/cpu-evaluator/src/main.rs"
            negative = root / "negative.rs"
            original = source.read_text()
            changed = original.replace("EVALUATOR_ARGUMENT", "EVALUATOR_ARGUMENT_NEGATIVE")
            if changed == original:
                raise ValueError("NATIVE_NEGATIVE_CONTROL_MISSING")
            negative.write_text(changed)
            altered = subjects(build(second, reference, epoch, changed_source=negative))
            if altered["kryvola-cpu-evaluator"] == expected["kryvola-cpu-evaluator"]:
                raise ValueError("NATIVE_CHANGED_SOURCE_ACCEPTED")
            print("M1_NATIVE_REPRODUCTION_PASSED", expected)
    finally:
        run("docker", "image", "rm", tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inside", "qualify"))
    parser.add_argument("--evaluator-only", action="store_true")
    args = parser.parse_args()
    if args.command == "inside":
        inside(args.evaluator_only)
    else:
        qualify()


if __name__ == "__main__":
    main()
