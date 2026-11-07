"""Test research wheels and qualify exact wheel bytes against external evidence."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if __package__:
    from . import dependency_policy, qualification, review_dispositions, review_successor
else:
    import dependency_policy
    import qualification
    import review_dispositions
    import review_successor

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, extra_env: dict[str, str] | None = None) -> None:
    print("+ " + " ".join(command), file=sys.stderr, flush=True)
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        stdout=sys.stderr,
        env=os.environ | {"CARGO_BUILD_JOBS": "2", "RAYON_NUM_THREADS": "2"} | (extra_env or {}),
    )


WHEEL_LIMIT = 128 << 20
REPOSITORY = "https://github.com/stanimirivanov/kryvola-engines"


def verify_wheel(
    wheel: Path,
    packet: Path,
    policy: Path,
    policy_sha256: str,
    source: str,
    lock_sha256: str,
    builder: str,
) -> dict:
    """Verify an exact wheel subject against the operator's independent pins."""
    require = dependency_policy.require
    require(
        re.fullmatch(r"kryvola_owner-[a-zA-Z0-9.]+-cp314-cp314-[a-zA-Z0-9_.]+\.whl", wheel.name)
        is not None,
        "WHEEL_SUBJECT",
    )
    require(
        review_successor.is_hex(source, 40)
        and review_successor.is_hex(lock_sha256, 64)
        and review_successor.is_hex(builder, 88)
        and builder.startswith(review_successor.ED25519_SPKI),
        "WHEEL_TRUST_INPUT",
    )
    qualification.validate(ROOT)
    digest = review_successor.sha256(review_successor.read(wheel, WHEEL_LIMIT))
    review = review_successor.verify(
        packet,
        policy,
        policy_sha256,
        qualification.digest(ROOT / review_dispositions.RECORD),
        "artifact_distribution",
        digest,
    )
    expected = {
        "role": "owner-wheel",
        "repository": REPOSITORY,
        "source": source,
        "cargo_lock_sha256": lock_sha256,
        "subject": {"name": wheel.name, "sha256": digest},
    }
    data = review_successor.read(packet / "provenance.json", 16384)
    require(
        review_successor.document(data, set(expected)) == {"version": 1, **expected},
        "WHEEL_PROVENANCE",
    )
    review_successor.verify_signatures(packet, data, {"builder": builder})
    return {
        "wheel_sha256": digest,
        "wheel": wheel.name,
        "source": source,
        "cargo_lock_sha256": lock_sha256,
        "provenance_sha256": review_successor.sha256(data),
        "builder_key_sha256": review_successor.sha256(bytes.fromhex(builder)),
        "review": review,
    }


def install_and_test(wheel: Path, root: Path) -> None:
    environment = root / "installed"
    run("uv", "venv", "--python", sys.executable, str(environment))
    python = environment / "bin/python"
    run(
        "uv",
        "pip",
        "install",
        "--python",
        str(python),
        "--no-index",
        "--no-deps",
        "--no-cache",
        str(wheel),
    )
    (root / "kryvola_owner.py").write_text(
        'raise RuntimeError("owner wheel import escaped isolation")\n', encoding="utf-8"
    )
    run(
        str(python),
        "-I",
        str(ROOT / "tests/owner_wheel.py"),
        extra_env={"PYTHONPATH": os.pathsep.join((str(root), str(ROOT)))},
    )


def qualify_and_test(
    wheel: Path,
    packet: Path,
    policy: Path,
    policy_sha256: str,
    source: str,
    lock_sha256: str,
    builder: str,
) -> dict:
    # Verify and install the same private snapshot, even if the caller replaces the input.
    with tempfile.TemporaryDirectory(prefix="owner-wheel-qualification-") as directory:
        root = Path(directory)
        snapshot = root / wheel.name
        snapshot.write_bytes(review_successor.read(wheel, WHEEL_LIMIT))
        report = verify_wheel(snapshot, packet, policy, policy_sha256, source, lock_sha256, builder)
        install_and_test(snapshot, root)
        dependency_policy.require(
            int(time.time()) < report["review"]["valid_until"], "REVIEW_EXPIRED_DURING_INSTALL"
        )
    return {"distribution": "QUALIFIED", **report}


def main() -> None:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise SystemExit("owner wheel requires CPython 3.14")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--policy-sha256")
    parser.add_argument("--source")
    parser.add_argument("--lock-sha256")
    parser.add_argument("--builder")
    args = vars(parser.parse_args())
    if any(value is not None for value in args.values()):
        if not all(args.values()):
            parser.error("wheel qualification requires all seven options")
        try:
            print(json.dumps(qualify_and_test(**args), sort_keys=True))
        except ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError:
            print('{"distribution":"DENY"}', file=sys.stderr)
            raise SystemExit(1) from None
        return

    dependency_policy.validate(ROOT)
    with tempfile.TemporaryDirectory(prefix="owner-wheel-") as temporary:
        root = Path(temporary)
        wheels = root / "wheels"
        run(
            "maturin",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "crates/owner-crypto/python/Cargo.toml",
            "--interpreter",
            sys.executable,
            "--out",
            str(wheels),
        )
        (wheel,) = wheels.glob("*.whl")
        digest = review_successor.sha256(review_successor.read(wheel, WHEEL_LIMIT))
        print(f"research wheel sha256={digest} distribution=DENY", flush=True)
        run(sys.executable, "-m", "tests.test_wheel_qualification", str(wheel))


if __name__ == "__main__":
    main()
