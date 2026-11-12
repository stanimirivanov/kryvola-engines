"""M1 CPU/owner delivery with explicit solo-owner development approval, separate from M0."""

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
from pathlib import Path

if __package__:
    from . import native_build, owner_wheel, qualification, release, review_successor
else:
    import native_build
    import owner_wheel
    import qualification
    import release
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
    "Native-Build.Dockerfile": "containers/Native-Build.Dockerfile",
    "rust-toolchain.toml": "rust-toolchain.toml",
}
OWNER = "stanimirivanov"
APPROVAL = "owner-approval.json"


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
        names |= {APPROVAL, "image.json"}
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
        "schema_version": "engines-m1-v1" if state == "CANDIDATE" else "engines-m1-v2",
        "source": source,
        "state": state,
        "distribution": "DENY" if state == "CANDIDATE" else "OWNER_APPROVED_DEVELOPMENT_ONLY",
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
        names |= {APPROVAL, "image.json"}
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
        manifest["schema_version"] == ("engines-m1-v2" if approved else "engines-m1-v1")
        and manifest["source"] == source
        and manifest["state"] == state
    )
    require(
        manifest["distribution"] == ("OWNER_APPROVED_DEVELOPMENT_ONLY" if approved else "DENY")
        and manifest["production_ready"] is False
    )
    require(
        set(manifest["subjects"]) == names
        and {p.name for p in folder.iterdir()}
        <= names | {"manifest.json", "manifest.sigstore.json", APPROVAL}
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
        permissions(folder, source)
        image = release.read(folder / "image.json")
        require(
            set(image) == {"source", "image", "cpu_sha256"}
            and image["source"] == source
            and image["cpu_sha256"] == sha(folder / "cpu-runtime.tar")
        )
        require(re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", image["image"]))
    return manifest


def owner_context(source):
    expected = {
        "GITHUB_ACTOR": OWNER,
        "GITHUB_REPOSITORY": f"{OWNER}/kryvola-engines",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": source,
        "GITHUB_WORKFLOW_REF": IDENTITY.removeprefix("https://github.com/"),
    }
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    require(
        all(os.environ.get(key) == value for key, value in expected.items())
        and re.fullmatch(r"[1-9][0-9]{0,29}", run_id),
        "OWNER_DISPATCH_REQUIRED",
    )
    return run_id


def approval_subject(folder, source):
    return {
        "schema_version": "solo-owner-development-v1",
        "owner": OWNER,
        "source": source,
        "cpu_sha256": sha(folder / "cpu-runtime.tar"),
        "owner_sha256": sha(wheel(folder)),
        "image_sha256": release.read(folder / "image-subject.json")["config_sha256"],
        "intended_use": "development_distribution",
        "independent_review": False,
        "production_ready": False,
    }


def permissions(folder, source):
    """An owner decision for development only; not independent review or a rights grant."""
    value = json.loads(review_successor.read(folder / APPROVAL, 4096))
    expected = approval_subject(folder, source)
    require(isinstance(value, dict) and set(value) == set(expected) | {"run_id"})
    require(all(value[key] == expected[key] for key in expected))
    require(value["independent_review"] is False and value["production_ready"] is False)
    require(isinstance(value["run_id"], str) and re.fullmatch(r"[1-9][0-9]{0,29}", value["run_id"]))
    return value


def image_reference(image):
    """Docker-addressable immutable reference; not necessarily a configuration digest."""
    value = release.run(
        "docker", "image", "inspect", image, "--format", "{{.Id}}", capture_output=True, text=True
    ).stdout.strip()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    return value


def image_identity(image):
    """Hash the actual configuration bytes from a single-image Docker save archive."""
    reference = image_reference(image)
    with tempfile.TemporaryDirectory(prefix="m1-image-config-") as temporary:
        path = Path(temporary) / "image.tar"
        release.run("docker", "image", "save", "--output", path, reference, timeout=120)
        with tarfile.open(path, "r:") as stream:
            members = stream.getmembers()

            def member_bytes(name, limit):
                matches = [item for item in members if item.name == name]
                require(len(matches) == 1, "IMAGE_CONFIG_ARCHIVE")
                entry = matches[0]
                require(entry.isfile() and 0 < entry.size <= limit, "IMAGE_CONFIG_ARCHIVE")
                contents = stream.extractfile(entry)
                if contents is None:
                    raise ValueError("IMAGE_CONFIG_ARCHIVE")
                data = contents.read(limit + 1)
                require(len(data) == entry.size, "IMAGE_CONFIG_ARCHIVE")
                return data

            manifest = json.loads(member_bytes("manifest.json", 64 << 10))
            require(isinstance(manifest, list) and len(manifest) == 1, "IMAGE_CONFIG_ARCHIVE")
            require(isinstance(manifest[0], dict), "IMAGE_CONFIG_ARCHIVE")
            name = manifest[0].get("Config")
            require(isinstance(name, str), "IMAGE_CONFIG_REFERENCE")
            match = re.fullmatch(r"(?:blobs/sha256/([0-9a-f]{64})|([0-9a-f]{64})\.json)", name)
            if match is None:
                raise ValueError("IMAGE_CONFIG_REFERENCE")
            data = member_bytes(name, 1 << 20)
            digest = hashlib.sha256(data).hexdigest()
            require(digest == (match[1] or match[2]), "IMAGE_CONFIG_DIGEST_MISMATCH")
            config = json.loads(data)
            require(
                isinstance(config, dict)
                and isinstance(config.get("architecture"), str)
                and isinstance(config.get("os"), str)
                and isinstance(config.get("config"), dict)
                and isinstance(config.get("rootfs"), dict)
                and config["rootfs"].get("type") == "layers"
                and isinstance(config["rootfs"].get("diff_ids"), list),
                "IMAGE_CONFIG_INVALID",
            )
            return digest


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
    with native_build.artifacts(epoch) as artifacts:
        assemble(source, env, artifacts)


def assemble(source, env, artifacts):
    release.run(
        sys.executable,
        ROOT / "tools/cpu_boundary.py",
        "--engine",
        artifacts / "kryvola-cpu-engine",
        "--evaluator",
        artifacts / "kryvola-cpu-evaluator",
        env=env,
    )
    release.run(
        sys.executable,
        ROOT / "tools/cpu_engine_package.py",
        artifacts / "kryvola-cpu-engine",
        artifacts / "kryvola-cpu-evaluator",
        env=env,
    )
    identity = image_identity("kryvola-cpu-engine:local")
    release.run(
        sys.executable,
        ROOT / "tools/cpu_engine_package.py",
        artifacts / "kryvola-cpu-engine",
        artifacts / "kryvola-cpu-evaluator",
        env=env,
    )
    require(image_identity("kryvola-cpu-engine:local") == identity, "IMAGE_NON_REPRODUCIBLE")
    paths = {
        "kryvola-cpu-engine": artifacts / "kryvola-cpu-engine",
        "kryvola-cpu-evaluator": artifacts / "kryvola-cpu-evaluator",
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
        (built,) = artifacts.glob("*.whl")
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


def publish(folder, source, cpu_sha256, owner_sha256, image_sha256):
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
        for name in set(manifest["subjects"]) | {"manifest.json", APPROVAL}:
            (folder / name).write_bytes(review_successor.read(destination / name, 128 << 20))
        validate(folder, source)
        require(
            sha(folder / "cpu-runtime.tar") == cpu_sha256
            and sha(wheel(folder)) == owner_sha256
            and release.read(folder / "image-subject.json")["config_sha256"] == image_sha256,
            "CANDIDATE_PIN",
        )
        require(
            permissions(folder, source)["run_id"] == owner_context(source), "OWNER_RUN_MISMATCH"
        )

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
        local_image = image_reference("kryvola-cpu-engine:local")
        image_check(local_image, contents)
        require(image_identity(local_image) == image_sha256, "IMAGE_REBUILD_MISMATCH")
        permissions(folder, source)
        tag = IMAGE + ":m1-" + source
        probe = release.run("docker", "manifest", "inspect", tag, check=False, capture_output=True)
        require(probe.returncode != 0, "M1_IMAGE_EXISTS")
        require(
            any(
                text in probe.stderr.lower() for text in (b"no such manifest", b"manifest unknown")
            ),
            "M1_IMAGE_LOOKUP_UNAVAILABLE",
        )
        release.run("docker", "tag", local_image, tag)
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
        release.write(
            folder / "image.json",
            {"source": source, "image": image, "cpu_sha256": sha(folder / "cpu-runtime.tar")},
        )
        seal(folder, source, "APPROVED")
        validate(folder, source, approved=True)
        permissions(folder, source)
        for path in folder.iterdir():
            shutil.copyfile(path, destination / path.name)


def authorize(folder, source, cpu_sha256, owner_sha256, image_sha256, *, approve=False):
    validate(folder, source)
    require(
        sha(folder / "cpu-runtime.tar") == cpu_sha256
        and sha(wheel(folder)) == owner_sha256
        and release.read(folder / "image-subject.json")["config_sha256"] == image_sha256,
        "CANDIDATE_PIN",
    )
    require(approve is True, "OWNER_APPROVAL_REQUIRED")
    approval = approval_subject(folder, source) | {"run_id": owner_context(source)}
    release.write(folder / APPROVAL, approval)
    return permissions(folder, source)


def verify(folder, source):
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
        "command", choices=("prepare", "check", "authorize", "publish-image", "verify")
    )
    parser.add_argument("--folder", type=Path, default=OUTPUT)
    parser.add_argument("--source")
    parser.add_argument("--cpu-sha256")
    parser.add_argument("--owner-sha256")
    parser.add_argument("--image-sha256")
    parser.add_argument("--approve-development-distribution", action="store_true")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "check":
        validate(args.folder, args.source)
    elif args.command in {"authorize", "publish-image"}:
        require(all((args.source, args.cpu_sha256, args.owner_sha256, args.image_sha256)))
        pins = (args.folder, args.source, args.cpu_sha256, args.owner_sha256, args.image_sha256)
        if args.command == "authorize":
            print(
                json.dumps(
                    authorize(*pins, approve=args.approve_development_distribution), sort_keys=True
                )
            )
        else:
            publish(*pins)
    else:
        require(args.source)
        verify(args.folder, args.source)


if __name__ == "__main__":
    main()
