"""CI-only real clean-target builds and local signature controls; never uploads."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

if __package__:
    from . import release
else:
    import release


def qualify(role):
    root = release.ROOT
    target = (root / "build" / ("repro-" + role)).resolve()
    if target.parent != (root / "build").resolve() or target.exists():
        raise ValueError("FRESH_CONFINED_TARGET_REQUIRED")
    first = root / "build" / (role + "-first")
    if first.exists() or (root / "build/packages" / role).exists():
        raise ValueError("FRESH_QUALIFICATION_REQUIRED")
    env = {**os.environ, "CARGO_BUILD_JOBS": "1"}
    command = [
        "cargo",
        "+1.98.1",
        "build",
        "--locked",
        "--release",
        "--jobs",
        "1",
        "--target-dir",
        str(target),
    ]
    if role == "fake-evaluator":
        command += ["-p", "kryvola-fake-engine"]
        name = "kryvola-fake-engine"
    elif role in {"cpu-evaluator", "owner-fixture"}:
        command += ["--manifest-path", "experiments/tfhe/Cargo.toml"]
        if role == "cpu-evaluator":
            command += ["--features", "compute-only"]
        name = "kryvola-tfhe-codec-experiment"
    else:
        command += ["--manifest-path", "experiments/sp1/Cargo.toml", "-p", "kryvola-sp1-host"]
        env.update(
            KRYVOLA_SP1_ELF=str(root / "build/sp1/elf/metadata.elf"),
            KRYVOLA_SP1_OTHER_ELF=str(root / "build/sp1/elf/alternate.elf"),
        )
        name = "kryvola-sp1-host"
    binary = target / "release" / name
    # A registry cache is reused; Cargo target output is rebuilt from scratch.
    for index in range(2):
        release.run(*command, cwd=root, env=env, timeout=2400)
        if index == 0:
            shutil.copy2(binary, first)
            shutil.rmtree(target)  # Checked exact generated target under build/ above.
    if role == "cpu-evaluator":
        for mode in ("owner", "frozen-owner", "compact-owner"):
            result = release.run(binary, mode, root / "build", check=False, capture_output=True)
            if result.returncode != 29:
                raise ValueError("COMPUTE_ACCEPTED_OWNER_ENTRYPOINT")
        with release.tempfile.TemporaryDirectory() as empty:
            result = release.run(
                binary, "evaluator", empty, "0" * 64, "0" * 64, check=False, capture_output=True
            )
            if result.returncode != 20:
                raise ValueError("COMPUTE_DECODER_NOT_REACHED")
    output = root / "build/packages" / role
    release.package(role, first, binary, output)
    prefix = root / "build" / (role + "-signer")
    key_env = {**os.environ, "COSIGN_PASSWORD": "ephemeral-ci-fixture"}
    release.run(
        release.tool("cosign"), "generate-key-pair", "--output-key-prefix", prefix, env=key_env
    )
    release.run(
        release.tool("cosign"),
        "sign-blob",
        "--yes",
        "--use-signing-config=false",
        "--tlog-upload=false",
        "--key",
        str(prefix) + ".key",
        "--bundle",
        output / "manifest.sigstore.json",
        output / "manifest.json",
        env=key_env,
    )
    release.verify(output, Path(str(prefix) + ".pub"))
    wrong = root / "build" / (role + "-wrong-signer")
    release.run(
        release.tool("cosign"), "generate-key-pair", "--output-key-prefix", wrong, env=key_env
    )
    try:
        release.verify(output, Path(str(wrong) + ".pub"))
    except subprocess.CalledProcessError:
        pass
    else:
        raise ValueError("WRONG_SIGNER_ACCEPTED")
    if role == "fake-evaluator":
        context = root / "build/runtime-fake"
        context.mkdir()
        with release.tarfile.open(output / "package.tar") as archive:
            for name in ("engine", "LICENSE", "Cargo.lock"):
                stream = archive.extractfile(name)
                if stream is None:
                    raise ValueError("MISSING_CONTEXT_FILE")
                (context / name).write_bytes(stream.read())
        (context / "engine").chmod(0o755)
        release.run(
            "docker",
            "build",
            "-f",
            root / "containers/Dockerfile",
            "-t",
            "kryvola-runtime-check",
            context,
        )
        release.run(
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--network=none",
            "--tmpfs",
            "/tmp",
            "kryvola-runtime-check",
            "conformance",
        )
    if role == "fake-evaluator":
        release.run(
            "docker", "save", "--output", root / "build/runtime-fake.tar", "kryvola-runtime-check"
        )
    print(
        f"QUALIFIED_LOCAL_ONLY={role}; two clean target builds; real signature/wrong-signer control"
    )


if __name__ == "__main__":
    if sys.platform != "linux" or len(sys.argv) != 2:
        raise ValueError("LINUX_CI_ROLE_REQUIRED")
    if sys.argv[1] not in {"native", "sp1", "fake"}:
        raise ValueError("UNKNOWN_QUALIFICATION_GROUP")
    release.install()
    if sys.argv[1] == "sp1":
        # Proof measurements are complete. Free their generated host target so
        # two further clean builds fit hosted-runner disk; retain pinned ELFs.
        previous = release.ROOT / "build/sp1/host-target"
        if previous.exists():
            if previous.resolve() != previous.absolute():
                raise ValueError("UNEXPECTED_HOST_TARGET")
            shutil.rmtree(previous)
    roles = {
        "native": ["fake-evaluator", "cpu-evaluator", "owner-fixture"],
        "sp1": ["local-prover"],
        "fake": ["fake-evaluator"],
    }[sys.argv[1]]
    for role in roles:
        qualify(role)
