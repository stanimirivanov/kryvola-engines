"""Offline research-candidate checks; not legal, build or runtime qualification."""

import argparse
import hashlib
import json
import re
import sys
import tomllib
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PURPOSES = {"local_research", "artifact_distribution", "commercial_service"}
OPTIONAL = {
    "risc-zero",
    "openfhe",
    "seal",
    "tenseal",
    "mp-spdz",
    "syft",
    "cosign",
    "redpanda",
    "seaweedfs",
}
SOURCES = {
    "tfhe": ("https://github.com/zama-ai/tfhe-rs", "BSD-3-Clause-Clear"),
    "sp1-sdk": ("https://github.com/succinctlabs/sp1", "MIT OR Apache-2.0"),
}
DEFERRED_DIRECT = OPTIONAL | {"tfhe-cuda-backend", "sp1-cuda", "risc0-zkvm"}


class PolicyError(ValueError):
    """Stable policy failure, never an automated legal approval."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyError(code)


def fields(value: Any, names: set[str]) -> None:
    require(type(value) is dict and set(value) == names, "INVALID_FIELDS")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        require(key not in value, "DUPLICATE_KEY")
        value[key] = child
    return value


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(1048577)
    require(len(raw) <= 1048576, "METADATA_LIMIT")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    require(type(value) is dict, "INVALID_FIELDS")
    return value


def _version(value: str) -> tuple[int, ...]:
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value) is not None,
        "MISSING_PIN",
    )
    parts = tuple(map(int, value.split(".")))
    return parts + (0,) * (3 - len(parts))


def validate(root: Path = ROOT) -> dict[str, Any]:
    policy = _read_json(root / "config/dependency-policy.json")
    fields(
        policy, {"schema_version", "stage", "observed_on", "toolchain", "candidates", "optional"}
    )
    require(
        type(policy["schema_version"]) is int
        and policy["schema_version"] == 1
        and policy["stage"] == "M0_RESEARCH_CANDIDATES",
        "INVALID_STAGE",
    )
    require(
        date.fromisoformat(policy["observed_on"]).isoformat() == policy["observed_on"],
        "INVALID_DATE",
    )
    fields(policy["toolchain"], {"rust", "python", "uv"})
    toolchain = policy["toolchain"]
    rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    require(
        toolchain
        == {
            "rust": rust,
            "python": (root / ".python-version").read_text().strip(),
            "uv": project["tool"]["uv"]["required-version"].removeprefix("=="),
        },
        "TOOLCHAIN_DRIFT",
    )
    require(
        type(policy["candidates"]) is list and len(policy["candidates"]) == len(SOURCES),
        "MISSING_PIN",
    )
    seen = set()
    for item in policy["candidates"]:
        fields(
            item,
            {
                "name",
                "version",
                "repository",
                "source_revision",
                "artifact",
                "license",
                "evidence",
                "permissions",
                "legal_review",
                "features",
                "default_features",
                "compatibility",
            },
        )
        name, version = item["name"], item["version"]
        require(name in SOURCES and name not in seen, "MISSING_PIN")
        seen.add(name)
        _version(version)
        require(
            len(version.split(".")) == 3
            and re.fullmatch("[0-9a-f]{40}", item["source_revision"]) is not None,
            "MISSING_PIN",
        )
        require(
            (item["repository"], item["license"]) == SOURCES[name], "SOURCE_OR_LICENSE_MISMATCH"
        )
        fields(item["artifact"], {"url", "sha256", "bytes"})
        artifact = item["artifact"]
        require(
            artifact["url"] == f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
            and re.fullmatch("[0-9a-f]{64}", artifact["sha256"]) is not None
            and type(artifact["bytes"]) is int
            and 0 < artifact["bytes"] <= 16777216,
            "MISSING_PIN",
        )
        expected = {"Cargo.toml", ".cargo_vcs_info.json", "registry.json", "notice.json"}
        expected |= {"LICENSE"} if name == "tfhe" else {"LICENSE-MIT", "LICENSE-APACHE"}
        fields(item["evidence"], expected)
        paths = {}
        for filename, evidence in item["evidence"].items():
            fields(evidence, {"path", "sha256", "source"})
            path = root / f"config/dependency-evidence/{name}" / filename
            require(
                evidence["path"] == path.relative_to(root).as_posix()
                and path.resolve().is_relative_to(root.resolve())
                and not path.is_symlink(),
                "UNSAFE_EVIDENCE",
            )
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == evidence["sha256"],
                "EVIDENCE_MISMATCH",
            )
            source = (
                f"https://crates.io/api/v1/crates/{name}/{version}"
                if filename == "registry.json"
                else artifact["url"] + "#" + filename
                if filename in {"Cargo.toml", ".cargo_vcs_info.json"}
                else f"https://raw.githubusercontent.com/{item['repository'].removeprefix('https://github.com/')}/{item['source_revision']}/"
                + ("README.md" if filename == "notice.json" else filename)
            )
            require(evidence["source"] == source, "EVIDENCE_SOURCE_MISMATCH")
            paths[filename] = path
        metadata = _read_json(paths["registry.json"])["version"]
        package = tomllib.loads(paths["Cargo.toml"].read_text())["package"]
        vcs = _read_json(paths[".cargo_vcs_info.json"])
        require(
            package["name"] == name
            and package["version"] == metadata["num"] == version
            and package["license"] == metadata["license"] == item["license"]
            and metadata["checksum"] == artifact["sha256"]
            and vcs["git"]["sha1"] == item["source_revision"]
            and not vcs["git"].get("dirty", False),
            "METADATA_MISMATCH",
        )
        require(
            _version(package["rust-version"]) == _version(metadata["rust_version"])
            and _version(rust) >= _version(package["rust-version"]),
            "DECLARED_COMPILER_MISMATCH",
        )
        notice = _read_json(paths["notice.json"])
        fields(notice, {"source", "document_sha256", "observed_on", "scope", "summary"})
        require(
            notice["source"] == item["evidence"]["notice.json"]["source"]
            and re.fullmatch("[0-9a-f]{64}", notice["document_sha256"]) is not None
            and notice["observed_on"] == policy["observed_on"],
            "NOTICE_MISMATCH",
        )
        require(
            item["permissions"]
            == {
                "local_research": "RESEARCH_ONLY",
                "artifact_distribution": "DENY",
                "commercial_service": "DENY",
            }
            and item["legal_review"] == "PENDING",
            "UNAUTHORIZED_USE",
        )
        require(
            item["default_features"] is False
            and type(item["features"]) is list
            and len(set(item["features"])) == len(item["features"]),
            "UNAPPROVED_FEATURES",
        )
        available = tomllib.loads(paths["Cargo.toml"].read_text())["features"]
        allowed = {"integer", "software-prng", "zk-pok"} if name == "tfhe" else set()
        require(set(item["features"]) <= set(available) & allowed, "UNAPPROVED_FEATURES")
        require(
            item["compatibility"]
            == {
                "target": "x86_64-unknown-linux-gnu",
                "rustc": rust,
                "status": "NOT_BUILT",
                "native_compiler": "NOT_VERIFIED",
                "cuda": "NOT_USED",
                "python_wheel": "NOT_USED",
                "guest_toolchain": "NOT_PINNED" if name == "sp1-sdk" else "NOT_USED",
            },
            "UNQUALIFIED_COMBINATION",
        )
    fields(policy["optional"], OPTIONAL)
    for name, item in policy["optional"].items():
        fields(item, {"disposition", "reason"})
        require(
            item["disposition"] == ("BUILD_TOOL_ONLY" if name in {"syft", "cosign"} else "DEFERRED")
            and isinstance(item["reason"], str)
            and bool(item["reason"]),
            "UNKNOWN_DISPOSITION",
        )
    _consumers(root, {item["name"]: item for item in policy["candidates"]})
    return policy


def _consumers(root: Path, pins: Mapping[str, Any]) -> None:
    """Check direct declarations and lock identities; not Cargo feature resolution."""
    for folder, directories, filenames in root.walk():
        directories[:] = [
            name
            for name in directories
            if name not in {".git", ".venv", "target", "build", "contracts", "dependency-evidence"}
        ]
        if "Cargo.toml" in filenames:
            data = tomllib.loads((folder / "Cargo.toml").read_text())
            aliases = {}
            require(
                not any(name.split(":")[0] in pins for name in data.get("replace", {})),
                "UNPINNED_CONSUMER",
            )
            require(
                not any(
                    name in pins or value.get("package") in pins
                    for group in data.get("patch", {}).values()
                    for name, value in group.items()
                    if isinstance(value, dict)
                ),
                "UNPINNED_CONSUMER",
            )
            for section in [data, data.get("workspace", {}), *data.get("target", {}).values()]:
                for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for alias, declaration in section.get(group, {}).items():
                        name = (
                            declaration.get("package", alias)
                            if isinstance(declaration, dict)
                            else alias
                        )
                        require(name not in DEFERRED_DIRECT, "DEFERRED_DEPENDENCY")
                        if name not in pins:
                            continue
                        aliases[alias] = name
                        require(type(declaration) is dict, "UNPINNED_CONSUMER")
                        require(
                            declaration.get("version") == "=" + pins[name]["version"]
                            and declaration.get("default-features") is False
                            and not {"path", "git", "registry", "workspace"}.intersection(
                                declaration
                            )
                            and set(declaration.get("features", [])) == set(pins[name]["features"]),
                            "UNPINNED_CONSUMER",
                        )
            for features in data.get("features", {}).values():
                for feature in features:
                    alias, separator, forwarded = feature.partition("/")
                    name = aliases.get(alias.removesuffix("?"))
                    if separator and name:
                        require(forwarded in pins[name]["features"], "UNAPPROVED_FEATURES")
        if "Cargo.lock" in filenames:
            for package in tomllib.loads((folder / "Cargo.lock").read_text()).get("package", []):
                if package["name"] in pins:
                    pin = pins[package["name"]]
                    require(
                        package["version"] == pin["version"]
                        and package.get("checksum") == pin["artifact"]["sha256"]
                        and package.get("source")
                        == "registry+https://github.com/rust-lang/crates.io-index",
                        "UNPINNED_CONSUMER",
                    )


def admit(policy: dict[str, Any], candidate: str, purpose: str) -> dict[str, Any]:
    require(purpose in PURPOSES and purpose == "local_research", "UNAUTHORIZED_USE")
    matches = [item for item in policy["candidates"] if item["name"] == candidate]
    require(len(matches) == 1, "MISSING_PIN")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--candidate")
    parser.add_argument("--purpose", choices=sorted(PURPOSES))
    parser.add_argument("--artifact", type=Path)
    args = parser.parse_args()
    try:
        policy = validate(args.root)
        if args.candidate or args.purpose or args.artifact:
            pin = admit(policy, args.candidate, args.purpose)
            if args.artifact:
                require(
                    args.artifact.stat().st_size == pin["artifact"]["bytes"], "ARTIFACT_MISMATCH"
                )
                with args.artifact.open("rb") as stream:
                    require(
                        hashlib.file_digest(stream, "sha256").hexdigest()
                        == pin["artifact"]["sha256"],
                        "ARTIFACT_MISMATCH",
                    )
        print("Research candidates valid; builds unverified; distribution/service denied.")
        return 0
    except ValueError, KeyError, TypeError, OSError, AttributeError:
        print("dependency-policy: REJECTED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
