"""M1 CPU/owner candidate and permission-gated publication, separate from M0."""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

if __package__:
    from . import owner_wheel, qualification, release, review_dispositions, review_successor
else:
    import owner_wheel
    import qualification
    import release
    import review_dispositions
    import review_successor

ROOT = release.ROOT
OUTPUT = ROOT / "build/m1"
IDENTITY = "https://github.com/stanimirivanov/kryvola-engines/.github/workflows/m1-release.yml@refs/heads/main"
IMAGE = "ghcr.io/stanimirivanov/kryvola-engines/cpu-engine"
CPU_FILES = {"kryvola-cpu-engine", "kryvola-cpu-evaluator", "cpu_runner.py", "LICENSE"}
INPUTS = {
    "Cargo.lock": "Cargo.lock",
    "evaluator.lock": "crates/cpu-evaluator/Cargo.lock",
    "owner.lock": "crates/owner-crypto/Cargo.lock",
    "spec.lock.json": "spec.lock.json",
    "CPU-Engine.Dockerfile": "containers/CPU-Engine.Dockerfile",
    "rust-toolchain.toml": "rust-toolchain.toml",
}
EVIDENCE = (
    {"policy.json"}
    | {
        f"{role}/{name}"
        for role in ("cpu", "image", "owner")
        for name in ("decision.json", "legal.sig", "parameters.sig")
    }
    | {"owner/provenance.json", "owner/builder.sig"}
)


def require(value, code="M1_RELEASE_REJECTED"):
    if not value:
        raise ValueError(code)


def sha(path):
    return hashlib.sha256(review_successor.read(Path(path), 128 << 20)).hexdigest()


def archive(path, contents):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as stream:
        for name, data in sorted(contents.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o755 if name.startswith("kryvola-cpu-") else 0o644
            stream.addfile(entry, io.BytesIO(data))


def unpack(path, allowed, limit):
    result = {}
    with tarfile.open(path) as stream:
        for entry in stream:
            require(entry.isfile() and entry.name in allowed and entry.name not in result)
            require(0 <= entry.size <= limit and len(result) < len(allowed))
            member = stream.extractfile(entry)
            if member is None:
                raise ValueError("M1_RELEASE_REJECTED")
            result[entry.name] = member.read(limit + 1)
            require(len(result[entry.name]) == entry.size)
    require(set(result) == allowed)
    return result


def wheel(folder):
    matches = list(folder.glob("kryvola_owner-*.whl"))
    require(
        len(matches) == 1
        and re.fullmatch(
            r"kryvola_owner-0\.1\.0\.dev2-cp314-cp314-[a-zA-Z0-9_.]+\.whl", matches[0].name
        )
    )
    return matches[0]


def seal(folder, source, state):
    require(review_successor.is_hex(source, 40) and state in {"CANDIDATE", "APPROVED"})
    names = set(INPUTS) | {"cpu-runtime.tar", wheel(folder).name, "sbom.json", "image-subject.json"}
    if state == "APPROVED":
        names |= {"permission-evidence.tar", "image.json"}
    release.write(
        folder / "provenance.json",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"name": name, "digest": {"sha256": sha(folder / name)}} for name in sorted(names)
            ],
            "predicate": {
                "buildDefinition": {
                    "buildType": IDENTITY + "/m1/v1",
                    "externalParameters": {
                        "source": source,
                        "spec": release.read(folder / "spec.lock.json"),
                    },
                },
                "runDetails": {
                    "builder": {"id": os.environ.get("GITHUB_WORKFLOW_REF", "LOCAL_QUALIFICATION")}
                },
            },
        },
    )
    names.add("provenance.json")
    manifest = {
        "schema_version": "engines-m1-v1",
        "source": source,
        "state": state,
        "distribution": "DENY" if state == "CANDIDATE" else "SCOPED_ARTIFACT_DISTRIBUTION",
        "spec": release.read(folder / "spec.lock.json"),
        "production_ready": False,
        "subjects": {name: sha(folder / name) for name in sorted(names)},
    }
    release.write(folder / "manifest.json", manifest)
    return manifest


def validate(folder, source, *, approved=False):
    require(review_successor.is_hex(source, 40))
    manifest = release.read(folder / "manifest.json")
    state = "APPROVED" if approved else "CANDIDATE"
    names = set(INPUTS) | {
        "cpu-runtime.tar",
        wheel(folder).name,
        "sbom.json",
        "provenance.json",
        "image-subject.json",
    }
    if approved:
        names |= {"permission-evidence.tar", "image.json"}
    require(
        set(manifest)
        == {
            "schema_version",
            "source",
            "state",
            "distribution",
            "spec",
            "production_ready",
            "subjects",
        }
    )
    require(
        manifest["schema_version"] == "engines-m1-v1"
        and manifest["source"] == source
        and manifest["state"] == state
    )
    require(
        manifest["distribution"] == ("SCOPED_ARTIFACT_DISTRIBUTION" if approved else "DENY")
        and manifest["production_ready"] is False
    )
    require(
        set(manifest["subjects"]) == names
        and {p.name for p in folder.iterdir()}
        <= names | {"manifest.json", "manifest.sigstore.json"}
    )
    require(all(sha(folder / name) == digest for name, digest in manifest["subjects"].items()))
    require(manifest["spec"] == release.read(ROOT / "spec.lock.json"))
    require(all(sha(folder / name) == sha(ROOT / original) for name, original in INPUTS.items()))
    subject = release.read(folder / "image-subject.json")
    require(
        set(subject) == {"source", "cpu_sha256", "config_sha256"}
        and subject["source"] == source
        and subject["cpu_sha256"] == sha(folder / "cpu-runtime.tar")
        and review_successor.is_hex(subject["config_sha256"], 64)
    )
    unpack(folder / "cpu-runtime.tar", CPU_FILES, 128 << 20)
    provenance = release.read(folder / "provenance.json")
    require(
        provenance["_type"] == "https://in-toto.io/Statement/v1"
        and provenance["predicateType"] == "https://slsa.dev/provenance/v1"
    )
    require(
        provenance["subject"]
        == [
            {"name": name, "digest": {"sha256": manifest["subjects"][name]}}
            for name in sorted(names - {"provenance.json"})
        ]
    )
    require(
        provenance["predicate"]["buildDefinition"]["externalParameters"]
        == {"source": source, "spec": manifest["spec"]}
    )
    if approved:
        image = release.read(folder / "image.json")
        require(
            set(image) == {"source", "image", "cpu_sha256"}
            and image["source"] == source
            and image["cpu_sha256"] == sha(folder / "cpu-runtime.tar")
        )
        require(re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", image["image"]))
    return manifest


def permissions(folder, source, packet, policy_sha256, builder):
    """Only independently pinned, current external decisions confer distribution permission."""
    require(review_successor.is_hex(policy_sha256, 64) and review_successor.is_hex(builder, 88))
    qualification.validate(ROOT)
    policy = packet / "policy.json"
    predecessor = qualification.digest(ROOT / review_dispositions.RECORD)
    cpu = review_successor.verify(
        packet / "cpu",
        policy,
        policy_sha256,
        predecessor,
        "artifact_distribution",
        sha(folder / "cpu-runtime.tar"),
    )
    image = review_successor.verify(
        packet / "image",
        policy,
        policy_sha256,
        predecessor,
        "artifact_distribution",
        release.read(folder / "image-subject.json")["config_sha256"],
    )
    owner = owner_wheel.verify_wheel(
        wheel(folder),
        packet / "owner",
        policy,
        policy_sha256,
        source,
        sha(ROOT / INPUTS["owner.lock"]),
        builder,
    )
    return {"cpu": cpu, "image": image, "owner": owner}


def fetch_evidence(url, expected, destination):
    require(urllib.parse.urlparse(url).scheme == "https" and review_successor.is_hex(expected, 64))
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20 and hashlib.sha256(raw).hexdigest() == expected)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "packet.tar"
        path.write_bytes(raw)
        contents = unpack(path, EVIDENCE, 16384)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in contents.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def image_identity(image):
    value = release.run(
        "docker", "image", "inspect", image, "--format", "{{.Id}}", capture_output=True, text=True
    ).stdout.strip()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    return value.removeprefix("sha256:")


def image_check(image, contents):
    config = json.loads(
        release.run(
            "docker",
            "image",
            "inspect",
            image,
            "--format",
            "{{json .Config}}",
            capture_output=True,
            text=True,
        ).stdout
    )
    require(
        config["User"] == "65532:65532"
        and config["Entrypoint"] == ["/opt/kryvola/kryvola-cpu-engine"]
    )
    container = release.run(
        "docker", "create", image, capture_output=True, text=True
    ).stdout.strip()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release.run("docker", "cp", container + ":/opt/kryvola/.", root)
            require({path.name for path in root.iterdir()} == CPU_FILES)
            require(
                all(
                    review_successor.read(root / name, 128 << 20) == data
                    for name, data in contents.items()
                )
            )
    finally:
        release.run("docker", "rm", container, stdout=subprocess.DEVNULL)
    result = release.run(
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--network",
        "none",
        "--entrypoint",
        "/opt/kryvola/kryvola-cpu-evaluator",
        image,
        "decrypt",
        check=False,
        capture_output=True,
    )
    require(result.returncode == 2 and result.stderr == b"EVALUATOR_ARGUMENT\n")


def prepare():
    source = release.run("git", "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    require(
        not release.run("git", "status", "--porcelain", capture_output=True, text=True).stdout
        and os.environ.get("GITHUB_SHA", source) == source,
        "CLEAN_PINNED_SOURCE_REQUIRED",
    )
    qualification.validate(ROOT)
    OUTPUT.mkdir(parents=True, exist_ok=False)
    epoch = release.run(
        "git", "show", "-s", "--format=%ct", "HEAD", capture_output=True, text=True
    ).stdout.strip()
    env = os.environ | {
        "CARGO_BUILD_JOBS": "2",
        "RAYON_NUM_THREADS": "2",
        "SOURCE_DATE_EPOCH": epoch,
    }
    release.run(
        "cargo", "build", "--release", "--locked", "-p", "kryvola-cpu-engine", env=env, timeout=2400
    )
    release.run(
        "cargo",
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        "crates/cpu-evaluator/Cargo.toml",
        env=env,
        timeout=2400,
    )
    release.run(sys.executable, ROOT / "tools/cpu_boundary.py", env=env)
    release.run(
        sys.executable,
        ROOT / "tools/cpu_engine_package.py",
        ROOT / "target/release/kryvola-cpu-engine",
        ROOT / "crates/cpu-evaluator/target/release/kryvola-cpu-evaluator",
        env=env,
    )
    identity = image_identity("kryvola-cpu-engine:local")
    release.run(
        sys.executable,
        ROOT / "tools/cpu_engine_package.py",
        ROOT / "target/release/kryvola-cpu-engine",
        ROOT / "crates/cpu-evaluator/target/release/kryvola-cpu-evaluator",
        env=env,
    )
    require(image_identity("kryvola-cpu-engine:local") == identity, "IMAGE_NON_REPRODUCIBLE")
    paths = {
        "kryvola-cpu-engine": ROOT / "target/release/kryvola-cpu-engine",
        "kryvola-cpu-evaluator": ROOT / "crates/cpu-evaluator/target/release/kryvola-cpu-evaluator",
        "cpu_runner.py": ROOT / "tools/cpu_runner.py",
        "LICENSE": ROOT / "LICENSE",
    }
    contents = {name: review_successor.read(path, 128 << 20) for name, path in paths.items()}
    archive(OUTPUT / "cpu-runtime.tar", contents)
    image_check("kryvola-cpu-engine:local", contents)
    release.write(
        OUTPUT / "image-subject.json",
        {
            "source": source,
            "cpu_sha256": sha(OUTPUT / "cpu-runtime.tar"),
            "config_sha256": identity,
        },
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        release.run(
            "maturin",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "crates/owner-crypto/python/Cargo.toml",
            "--interpreter",
            sys.executable,
            "--out",
            root / "wheels",
            env=env,
            timeout=2400,
        )
        (built,) = (root / "wheels").glob("*.whl")
        owner_wheel.install_and_test(built, root)
        shutil.copyfile(built, OUTPUT / built.name)
    for name, original in INPUTS.items():
        shutil.copyfile(ROOT / original, OUTPUT / name)
    release.run(
        release.tool("syft"),
        "scan",
        "dir:" + str(OUTPUT),
        "-o",
        "spdx-json=" + str(OUTPUT / "sbom.json"),
    )
    seal(OUTPUT, source, "CANDIDATE")
    validate(OUTPUT, source)
    print(
        json.dumps(
            {
                "source": source,
                "manifest_sha256": sha(OUTPUT / "manifest.json"),
                "distribution": "DENY",
            }
        )
    )


def publish(folder, source, cpu_sha256, owner_sha256, image_sha256, packet, policy_sha256, builder):
    manifest = validate(folder, source)
    require(
        sha(folder / "cpu-runtime.tar") == cpu_sha256
        and sha(wheel(folder)) == owner_sha256
        and release.read(folder / "image-subject.json")["config_sha256"] == image_sha256,
        "CANDIDATE_PIN",
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        destination = folder
        folder = root / "candidate"
        folder.mkdir(mode=0o700)
        for name in set(manifest["subjects"]) | {"manifest.json"}:
            (folder / name).write_bytes(review_successor.read(destination / name, 128 << 20))
        validate(folder, source)
        require(
            sha(folder / "cpu-runtime.tar") == cpu_sha256
            and sha(wheel(folder)) == owner_sha256
            and release.read(folder / "image-subject.json")["config_sha256"] == image_sha256,
            "CANDIDATE_PIN",
        )
        evidence = {name: review_successor.read(packet / name, 16384) for name in EVIDENCE}
        for name, data in evidence.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        permissions(folder, source, root, policy_sha256, builder)

        contents = unpack(folder / "cpu-runtime.tar", CPU_FILES, 128 << 20)
        for name, data in contents.items():
            (root / name).write_bytes(data)
            (root / name).chmod(0o755 if name.startswith("kryvola-cpu-") else 0o644)
        require(
            contents["cpu_runner.py"] == (ROOT / "tools/cpu_runner.py").read_bytes()
            and contents["LICENSE"] == (ROOT / "LICENSE").read_bytes()
        )
        release.run(
            sys.executable,
            ROOT / "tools/cpu_engine_package.py",
            root / "kryvola-cpu-engine",
            root / "kryvola-cpu-evaluator",
            env=os.environ
            | {
                "SOURCE_DATE_EPOCH": release.run(
                    "git", "show", "-s", "--format=%ct", source, capture_output=True, text=True
                ).stdout.strip()
            },
        )
        image_check("kryvola-cpu-engine:local", contents)
        require(
            image_identity("kryvola-cpu-engine:local") == image_sha256, "IMAGE_REBUILD_MISMATCH"
        )
        permissions(folder, source, root, policy_sha256, builder)
        tag = IMAGE + ":m1-" + source
        probe = release.run("docker", "manifest", "inspect", tag, check=False, capture_output=True)
        require(probe.returncode != 0, "M1_IMAGE_EXISTS")
        require(
            any(
                text in probe.stderr.lower() for text in (b"no such manifest", b"manifest unknown")
            ),
            "M1_IMAGE_LOOKUP_UNAVAILABLE",
        )
        release.run("docker", "tag", "kryvola-cpu-engine:local", tag)
        release.run("docker", "push", tag)
        refs = json.loads(
            release.run(
                "docker",
                "image",
                "inspect",
                tag,
                "--format",
                "{{json .RepoDigests}}",
                capture_output=True,
                text=True,
            ).stdout
        )
        (image,) = [ref for ref in refs if ref.startswith(IMAGE + "@sha256:")]
        release.run("docker", "pull", image)
        image_check(image, contents)
        require(image_identity(image) == image_sha256, "IMAGE_PULL_MISMATCH")
        archive(folder / "permission-evidence.tar", evidence)
        release.write(
            folder / "image.json",
            {"source": source, "image": image, "cpu_sha256": sha(folder / "cpu-runtime.tar")},
        )
        seal(folder, source, "APPROVED")
        validate(folder, source, approved=True)
        permissions(folder, source, root, policy_sha256, builder)
        for path in folder.iterdir():
            shutil.copyfile(path, destination / path.name)


def authorize(
    folder, source, cpu_sha256, owner_sha256, image_sha256, packet, policy_sha256, builder
):
    validate(folder, source)
    require(
        sha(folder / "cpu-runtime.tar") == cpu_sha256
        and sha(wheel(folder)) == owner_sha256
        and release.read(folder / "image-subject.json")["config_sha256"] == image_sha256,
        "CANDIDATE_PIN",
    )
    return permissions(folder, source, packet, policy_sha256, builder)


def verify(folder, source, policy_sha256, builder):
    validate(folder, source, approved=True)
    provenance = release.read(folder / "provenance.json")
    require(
        provenance["predicate"]["runDetails"]["builder"]["id"]
        == IDENTITY.removeprefix("https://github.com/")
    )
    release.run(
        release.tool("cosign"),
        "verify-blob",
        "--bundle",
        folder / "manifest.sigstore.json",
        "--certificate-identity",
        IDENTITY,
        "--certificate-oidc-issuer",
        release.ISSUER,
        "--certificate-github-workflow-sha",
        source,
        "--certificate-github-workflow-trigger",
        "workflow_dispatch",
        folder / "manifest.json",
        capture_output=True,
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name, data in unpack(folder / "permission-evidence.tar", EVIDENCE, 16384).items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        permissions(folder, source, root, policy_sha256, builder)
    image = release.read(folder / "image.json")["image"]
    release.run("docker", "pull", image)
    image_check(image, unpack(folder / "cpu-runtime.tar", CPU_FILES, 128 << 20))
    require(
        image_identity(image) == release.read(folder / "image-subject.json")["config_sha256"],
        "IMAGE_PULL_MISMATCH",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("prepare", "check", "fetch-evidence", "authorize", "publish-image", "verify"),
    )
    parser.add_argument("--folder", type=Path, default=OUTPUT)
    parser.add_argument("--source")
    parser.add_argument("--cpu-sha256")
    parser.add_argument("--owner-sha256")
    parser.add_argument("--image-sha256")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--policy-sha256")
    parser.add_argument("--builder")
    parser.add_argument("--url")
    parser.add_argument("--sha256")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "check":
        validate(args.folder, args.source)
    elif args.command == "fetch-evidence":
        require(all((args.url, args.sha256, args.packet)))
        fetch_evidence(args.url, args.sha256, args.packet)
    elif args.command in {"authorize", "publish-image"}:
        require(
            all(
                (
                    args.source,
                    args.cpu_sha256,
                    args.owner_sha256,
                    args.image_sha256,
                    args.packet,
                    args.policy_sha256,
                    args.builder,
                )
            )
        )
        result = (authorize if args.command == "authorize" else publish)(
            args.folder,
            args.source,
            args.cpu_sha256,
            args.owner_sha256,
            args.image_sha256,
            args.packet,
            args.policy_sha256,
            args.builder,
        )
        if args.command == "authorize":
            print(json.dumps(result, sort_keys=True))
    else:
        require(all((args.source, args.policy_sha256, args.builder)))
        verify(args.folder, args.source, args.policy_sha256, args.builder)


if __name__ == "__main__":
    main()
