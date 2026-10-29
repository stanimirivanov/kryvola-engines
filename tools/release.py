"""Experimental archive qualification. Crypto distribution remains denied."""

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

if __package__:
    from . import dependency_policy
else:
    import dependency_policy

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/release-tools"
IDENTITY = "https://github.com/stanimirivanov/kryvola-engines/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
ROLES = {
    "fake-evaluator": None,
    "cpu-evaluator": "tfhe",
    "owner-fixture": "tfhe",
    "local-prover": "sp1-sdk",
}
PINS = {
    "cosign": (
        "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64",
        "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    ),
    "syft": (
        "https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz",
        "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d",
    ),
}
EXECUTABLES = {
    "cosign": PINS["cosign"][1],
    "syft": "64c9631c3560336c55c549df0de08cd577d02399c9de807ac390960a4ed5c351",
}


def run(*args, **kwargs):
    kwargs.setdefault("check", True)
    kwargs.setdefault("timeout", 600)
    return subprocess.run(list(map(str, args)), **kwargs)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


def read(path):
    with path.open("rb") as stream:
        raw = stream.read((16 << 20) + 1)
    if len(raw) > 16 << 20:
        raise ValueError("METADATA_LIMIT")
    return json.loads(raw, object_pairs_hook=dependency_policy._pairs)


def tool(name):
    path = TOOLS / name
    # Recheck executable bytes on every use, not merely during installation.
    if sha(path) != EXECUTABLES[name]:
        raise ValueError("TOOL_INTEGRITY")
    return path


def install():
    if sys.platform != "linux":
        raise ValueError("LINUX_TOOLS_REQUIRED")
    TOOLS.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in PINS.items():
        with urllib.request.urlopen(url, timeout=60) as source:
            raw = source.read((160 << 20) + 1)
        if len(raw) > 160 << 20 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("TOOL_DOWNLOAD_PIN")
        if name == "syft":
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                member = archive.getmember("syft")
                if not member.isfile() or member.size > 160 << 20:
                    raise ValueError("TOOL_ARCHIVE")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("TOOL_ARCHIVE")
                raw = stream.read()
        path = TOOLS / name
        path.write_bytes(raw)
        path.chmod(0o700)
        tool(name)


def disposition(role, publish=False):
    policy = dependency_policy.validate()
    candidate = ROLES[role]
    if candidate:
        dependency_policy.admit(
            policy, candidate, "artifact_distribution" if publish else "local_research"
        )
        return "DENY"
    return "FAKE_ONLY_EXPERIMENTAL"


def package(role, first, second, output):
    permission = disposition(role)
    if sha(first) != sha(second):
        raise ValueError("NON_REPRODUCIBLE_BINARY")
    if (
        run(first.resolve(), "--artifact-role", capture_output=True, text=True).stdout.strip()
        != role
    ):
        raise ValueError("WRONG_BINARY_ROLE")
    output.mkdir(parents=True, exist_ok=False)
    source = run(
        "git", "rev-parse", "HEAD", cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    if (
        not re.fullmatch("[0-9a-f]{40}", source)
        or run("git", "status", "--porcelain", cwd=ROOT, capture_output=True).stdout
    ):
        raise ValueError("CLEAN_SOURCE_REQUIRED")
    lock = (
        ROOT
        / {
            "fake-evaluator": "Cargo.lock",
            "cpu-evaluator": "experiments/tfhe/Cargo.lock",
            "owner-fixture": "experiments/tfhe/Cargo.lock",
            "local-prover": "experiments/sp1/Cargo.lock",
        }[role]
    )
    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory)
        for name, source_path in (
            ("engine", first),
            ("LICENSE", ROOT / "LICENSE"),
            ("Cargo.lock", lock),
        ):
            (stage / name).write_bytes(source_path.read_bytes())
        with tarfile.open(output / "package.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(stage.iterdir()):
                entry = tarfile.TarInfo(path.name)
                entry.size, entry.mode = (
                    path.stat().st_size,
                    0o755 if path.name == "engine" else 0o644,
                )
                with path.open("rb") as stream:
                    archive.addfile(entry, stream)
        run(
            tool("syft"),
            "scan",
            "dir:" + str(stage),
            "-o",
            "spdx-json=" + str(output / "sbom.json"),
        )
    write(
        output / "provenance.json",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "package.tar", "digest": {"sha256": sha(output / "package.tar")}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/stanimirivanov/kryvola-engines/experimental-two-builds/v1",
                    "externalParameters": {"role": role},
                    "internalParameters": {
                        "first_binary_sha256": sha(first),
                        "second_binary_sha256": sha(second),
                    },
                    "resolvedDependencies": [
                        {
                            "uri": "git+https://github.com/stanimirivanov/kryvola-engines",
                            "digest": {"gitCommit": source},
                        },
                        {"uri": "Cargo.lock", "digest": {"sha256": sha(lock)}},
                    ],
                },
                "runDetails": {"builder": {"id": "LOCAL_QUALIFICATION_NOT_SLSA_ATTESTED"}},
            },
        },
    )
    write(
        output / "manifest.json",
        {
            "role": role,
            "source": source,
            "distribution": permission,
            "subjects": {
                name: sha(output / name) for name in ("package.tar", "sbom.json", "provenance.json")
            },
        },
    )


def verify(output, key=None, publish=False):
    manifest = read(output / "manifest.json")
    if (
        set(manifest) != {"role", "source", "distribution", "subjects"}
        or manifest["role"] not in ROLES
    ):
        raise ValueError("MANIFEST_FIELDS")
    if manifest["distribution"] != disposition(manifest["role"], publish):
        raise ValueError("DISPOSITION_MISMATCH")
    if publish and key is not None:
        raise ValueError("KEYED_PUBLICATION_FORBIDDEN")
    if (
        publish
        and manifest["source"]
        != run("git", "rev-parse", "HEAD", cwd=ROOT, capture_output=True, text=True).stdout.strip()
    ):
        raise ValueError("PUBLICATION_SOURCE_MISMATCH")
    if set(p.name for p in output.iterdir()) != {
        "manifest.json",
        "manifest.sigstore.json",
        "package.tar",
        "sbom.json",
        "provenance.json",
    }:
        raise ValueError("UNEXPECTED_PACKAGE_CONTENT")
    if any(
        p.is_symlink()
        or not p.is_file()
        or p.stat().st_size > ((512 << 20) if p.name == "package.tar" else (16 << 20))
        for p in output.iterdir()
    ):
        raise ValueError("PACKAGE_LIMIT_OR_LINK")
    if set(manifest["subjects"]) != {"package.tar", "sbom.json", "provenance.json"} or any(
        sha(output / name) != digest for name, digest in manifest["subjects"].items()
    ):
        raise ValueError("SUBJECT_MISMATCH")
    sbom = read(output / "sbom.json")
    if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages"):
        raise ValueError("MISSING_SBOM")
    provenance = read(output / "provenance.json")
    definition = provenance["predicate"]["buildDefinition"]
    builds = definition["internalParameters"]
    if (
        not re.fullmatch("[0-9a-f]{40}", manifest["source"])
        or provenance["_type"] != "https://in-toto.io/Statement/v1"
        or provenance["predicateType"] != "https://slsa.dev/provenance/v1"
        or provenance["subject"]
        != [{"name": "package.tar", "digest": {"sha256": sha(output / "package.tar")}}]
        or builds["first_binary_sha256"] != builds["second_binary_sha256"]
        or definition["externalParameters"] != {"role": manifest["role"]}
        or definition["resolvedDependencies"][0]["digest"] != {"gitCommit": manifest["source"]}
    ):
        raise ValueError("PROVENANCE_MISMATCH")
    with tarfile.open(output / "package.tar") as archive:
        members = archive.getmembers()
        if sorted(m.name for m in members) != ["Cargo.lock", "LICENSE", "engine"] or any(
            not m.isfile() for m in members
        ):
            raise ValueError("ARCHIVE_BOUNDARY")
        stream = archive.extractfile("engine")
        digest = hashlib.sha256()
        if stream is None:
            raise ValueError("BINARY_SUBJECT_MISMATCH")
        while chunk := stream.read(262_144):
            digest.update(chunk)
        if digest.hexdigest() != builds["first_binary_sha256"]:
            raise ValueError("BINARY_SUBJECT_MISMATCH")
        lock_stream = archive.extractfile("Cargo.lock")
        if lock_stream is None or archive.getmember("Cargo.lock").size > 16 << 20:
            raise ValueError("LOCK_SUBJECT_MISMATCH")
        lock_bytes = lock_stream.read()
        lock_digest = hashlib.sha256(lock_bytes).hexdigest()
        packages = tomllib.loads(lock_bytes.decode())["package"]
        if publish and any(p["name"] in dependency_policy.SOURCES for p in packages):
            raise ValueError("DISTRIBUTION_DENIED_LOCK")
        if definition["resolvedDependencies"] != [
            {
                "uri": "git+https://github.com/stanimirivanov/kryvola-engines",
                "digest": {"gitCommit": manifest["source"]},
            },
            {"uri": "Cargo.lock", "digest": {"sha256": lock_digest}},
        ]:
            raise ValueError("LOCK_SUBJECT_MISMATCH")
    args = (
        ["--key", key, "--insecure-ignore-tlog"]
        if key
        else ["--certificate-identity", IDENTITY, "--certificate-oidc-issuer", ISSUER]
    )
    run(
        tool("cosign"),
        "verify-blob",
        "--bundle",
        output / "manifest.sigstore.json",
        *args,
        output / "manifest.json",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["install", "package", "verify"])
    parser.add_argument("--role", choices=ROLES)
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--publish-check", action="store_true")
    args = parser.parse_args()
    if args.command == "install":
        install()
    elif args.command == "package":
        package(args.role, args.first, args.second, args.output)
    elif args.output:
        verify(args.output, args.key, args.publish_check)
    else:
        dependency_policy.validate()
        if args.publish_check or args.key:
            raise ValueError("PACKAGE_REQUIRED")
        print("Release configuration only; no signed package verified")


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
        tarfile.TarError,
        subprocess.SubprocessError,
    ):
        print("release: REJECTED", file=sys.stderr)
        sys.exit(1)
