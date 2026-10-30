"""Fake-only OCI publication and independently pinned image/archive verification."""

import argparse
import json
import re
import tempfile
from pathlib import Path

if __package__:
    from . import release
else:
    import release

IMAGE = "ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator"
OUTPUT = release.ROOT / "build/oci"


def image_ref(value):
    if not isinstance(value, str) or not re.fullmatch(
        re.escape(IMAGE) + r"@sha256:[a-f0-9]{64}", value
    ):
        raise ValueError("IMMUTABLE_FAKE_IMAGE_REQUIRED")
    return value


def runtime(image, package):
    release.run("docker", "pull", image)
    config = release.run(
        "docker",
        "image",
        "inspect",
        image,
        "--format",
        "{{json .Config}}",
        capture_output=True,
        text=True,
    )
    value = json.loads(config.stdout)
    if value["User"] != "65532:65532" or value["Entrypoint"] != ["/opt/kryvola/engine"]:
        raise ValueError("IMAGE_RUNTIME_BOUNDARY")
    container = release.run(
        "docker", "create", image, capture_output=True, text=True
    ).stdout.strip()
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release.run("docker", "cp", container + ":/opt/kryvola/.", root)
            with release.tarfile.open(package / "package.tar") as archive:
                if {p.name for p in root.iterdir()} != {"engine", "LICENSE", "Cargo.lock"}:
                    raise ValueError("OCI_OWNER_OR_EXTRA_FILE")
                for name in ("engine", "LICENSE", "Cargo.lock"):
                    path = root / name
                    stream = archive.extractfile(name)
                    if stream is None or path.is_symlink() or not path.is_file():
                        raise ValueError("OCI_PACKAGE_FILE")
                    if release.hashlib.sha256(stream.read()).hexdigest() != release.sha(path):
                        raise ValueError("OCI_ARCHIVE_BYTES_MISMATCH")
    finally:
        release.run("docker", "rm", container)
    release.run(
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--network=none",
        "--tmpfs",
        "/tmp",
        image,
        "conformance",
    )


def verify(folder, package, source, image):
    image_ref(image)
    if not re.fullmatch("[a-f0-9]{40}", source):
        raise ValueError("SOURCE_REQUIRED")
    release.verify(package, publish=True)
    archive = release.read(package / "manifest.json")
    if archive["source"] != source or archive["role"] != "fake-evaluator":
        raise ValueError("OCI_ARCHIVE_BINDING")
    if {p.name for p in folder.iterdir()} != {
        "manifest.json",
        "manifest.sigstore.json",
        "sbom.json",
        "provenance.json",
    }:
        raise ValueError("OCI_ASSET_BOUNDARY")
    if any(
        p.is_symlink() or not p.is_file() or p.stat().st_size > 16 << 20 for p in folder.iterdir()
    ):
        raise ValueError("OCI_ASSET_LIMIT")
    manifest = release.read(folder / "manifest.json")
    expected = {
        "format": "fake-oci-v1",
        "source": source,
        "image": image,
        "archive_manifest_sha256": release.sha(package / "manifest.json"),
        "dockerfile_sha256": release.sha(release.ROOT / "containers/Dockerfile"),
        "production_ready": False,
        "subjects": {name: release.sha(folder / name) for name in ("sbom.json", "provenance.json")},
    }
    if manifest != expected:
        raise ValueError("OCI_SUBJECT_MISMATCH")
    provenance = release.read(folder / "provenance.json")
    if provenance != statement(
        source, image, expected["archive_manifest_sha256"], expected["dockerfile_sha256"]
    ):
        raise ValueError("OCI_PROVENANCE_MISMATCH")
    sbom = release.read(folder / "sbom.json")
    if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages"):
        raise ValueError("OCI_SBOM_REQUIRED")
    identity = [
        "--certificate-identity",
        release.IDENTITY,
        "--certificate-oidc-issuer",
        release.ISSUER,
        "--certificate-github-workflow-sha",
        source,
        "--certificate-github-workflow-trigger",
        "workflow_dispatch",
    ]
    release.run(
        release.tool("cosign"),
        "verify-blob",
        "--bundle",
        folder / "manifest.sigstore.json",
        *identity,
        folder / "manifest.json",
        capture_output=True,
    )
    release.run(release.tool("cosign"), "verify", *identity, image, capture_output=True)
    runtime(image, package)


def statement(source, image, archive, dockerfile):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": IMAGE, "digest": {"sha256": image.split(":")[-1]}}],
        "predicate": {
            "source": source,
            "archive_manifest_sha256": archive,
            "dockerfile_sha256": dockerfile,
            "builder": release.IDENTITY,
            "scope": "FAKE_ONLY_EXPERIMENTAL_NOT_SLSA_LEVEL",
        },
    }


def publish(package, source):
    release.verify(package, publish=True)
    manifest = release.read(package / "manifest.json")
    if manifest["source"] != source or manifest["role"] != "fake-evaluator":
        raise ValueError("FAKE_SOURCE_REQUIRED")
    tag = IMAGE + ":experimental-" + source
    existing = release.run(
        "docker", "manifest", "inspect", tag, capture_output=True, text=True, check=False
    )
    if existing.returncode == 0:
        raise ValueError("OCI_VERSION_EXISTS")
    # Auth/network failures are not evidence that a version is absent.
    if not any(
        code in existing.stderr.lower()
        for code in ("manifest unknown", "no such manifest", "name unknown")
    ):
        raise ValueError("OCI_ABSENCE_UNCONFIRMED")
    OUTPUT.mkdir(parents=True, exist_ok=False)
    release.run("docker", "load", "--input", release.ROOT / "build/runtime-fake.tar")
    qualified_id = release.run(
        "docker",
        "image",
        "inspect",
        "kryvola-runtime-check",
        "--format",
        "{{.Id}}",
        capture_output=True,
        text=True,
    ).stdout.strip()
    release.run("docker", "tag", "kryvola-runtime-check", tag)
    release.run("docker", "push", tag)
    # Resolve once, then use only the immutable digest for all subsequent operations.
    release.run("docker", "pull", tag)
    result = release.run(
        "docker",
        "image",
        "inspect",
        tag,
        "--format",
        "{{json .RepoDigests}}",
        capture_output=True,
        text=True,
    )
    refs = [r for r in json.loads(result.stdout) if r.startswith(IMAGE + "@sha256:")]
    if len(refs) != 1:
        raise ValueError("OCI_DIGEST_AMBIGUOUS")
    image = image_ref(refs[0])
    pulled_id = release.run(
        "docker", "image", "inspect", image, "--format", "{{.Id}}", capture_output=True, text=True
    ).stdout.strip()
    if pulled_id != qualified_id:
        raise ValueError("QUALIFIED_IMAGE_CHANGED")
    runtime(image, package)
    release.run(
        release.tool("syft"),
        "scan",
        "registry:" + image,
        "-o",
        "spdx-json=" + str(OUTPUT / "sbom.json"),
    )
    archive = release.sha(package / "manifest.json")
    dockerfile = release.sha(release.ROOT / "containers/Dockerfile")
    release.write(OUTPUT / "provenance.json", statement(source, image, archive, dockerfile))
    release.write(
        OUTPUT / "manifest.json",
        {
            "format": "fake-oci-v1",
            "source": source,
            "image": image,
            "archive_manifest_sha256": archive,
            "dockerfile_sha256": dockerfile,
            "production_ready": False,
            "subjects": {
                name: release.sha(OUTPUT / name) for name in ("sbom.json", "provenance.json")
            },
        },
    )
    release.run(release.tool("cosign"), "sign", "--yes", image)
    release.run(
        release.tool("cosign"),
        "sign-blob",
        "--yes",
        "--bundle",
        OUTPUT / "manifest.sigstore.json",
        OUTPUT / "manifest.json",
    )
    verify(OUTPUT, package, source, image)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["publish", "verify"])
    parser.add_argument("--source", required=True)
    parser.add_argument(
        "--package", type=Path, default=release.ROOT / "build/packages/fake-evaluator"
    )
    parser.add_argument("--folder", type=Path, default=OUTPUT)
    parser.add_argument("--image")
    args = parser.parse_args()
    if args.command == "publish":
        publish(args.package, args.source)
    else:
        verify(args.folder, args.package, args.source, args.image)
