"""Install the pinned standalone protoc and .proto includes without apt or root."""

import hashlib
import io
import os
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

URL = "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip"
SHA256 = "3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8"
DESTINATION = Path(__file__).resolve().parents[1] / "build/sp1/protoc-21.12"
LIMIT = 2 << 20


def download() -> bytes:
    for attempt in range(3):
        try:
            with urllib.request.urlopen(URL, timeout=30) as response:
                raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError("PROTOC_DOWNLOAD_LIMIT")
            return raw
        except urllib.error.HTTPError as error:
            error.close()
            if error.code not in {408, 429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (OSError, urllib.error.URLError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)
    raise RuntimeError("PROTOC_DOWNLOAD_FAILED")


def contents(raw: bytes) -> dict[str, bytes]:
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("PROTOC_CHECKSUM_MISMATCH")
    result = {}
    with ZipFile(io.BytesIO(raw)) as archive:
        for entry in archive.infolist():
            name = entry.filename
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or name in result
                or stat.S_ISLNK(entry.external_attr >> 16)
                or not (
                    name in {"bin/protoc", "readme.txt"}
                    or name.startswith("include/google/protobuf/")
                    and name.endswith(".proto")
                )
                or entry.file_size > 16 << 20
                or len(result) >= 64
            ):
                raise ValueError("PROTOC_ARCHIVE_REJECTED")
            result[name] = archive.read(entry)
    if not {"bin/protoc", "include/google/protobuf/empty.proto"} <= result.keys():
        raise ValueError("PROTOC_ARCHIVE_REJECTED")
    return result


def install(destination: Path = DESTINATION) -> None:
    destination = destination.absolute()
    if destination.is_symlink():
        raise ValueError("PROTOC_CACHE_REJECTED")
    cached = destination.exists()
    if cached:
        path = destination / "archive.zip"
        if path.is_symlink():
            raise ValueError("PROTOC_CACHE_REJECTED")
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
    else:
        raw = download()
    files = contents(raw)
    if cached:
        paths = list(destination.rglob("*"))
        if (
            any(path.is_symlink() for path in paths)
            or {path.relative_to(destination).as_posix() for path in paths if path.is_file()}
            != set(files) | {"archive.zip"}
            or any(
                (destination / name).stat().st_size != len(data)
                or (destination / name).read_bytes() != data
                for name, data in files.items()
            )
        ):
            raise ValueError("PROTOC_CACHE_REJECTED")
    else:
        destination.mkdir(parents=True, exist_ok=False)
        (destination / "archive.zip").write_bytes(raw)
        for name, data in files.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name == "bin/protoc" else 0o644)
    executable = destination / "bin/protoc"
    result = subprocess.run(
        [str(executable), "--version"], check=True, timeout=10, capture_output=True, text=True
    )
    if result.stdout.strip() != "libprotoc 3.21.12":
        raise ValueError("PROTOC_VERSION_MISMATCH")
    if "GITHUB_ENV" in os.environ:
        with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
            stream.write(f"PROTOC={executable}\nPROTOC_INCLUDE={destination / 'include'}\n")
    if "GITHUB_PATH" in os.environ:
        with Path(os.environ["GITHUB_PATH"]).open("a") as stream:
            stream.write(str(destination / "bin") + "\n")
    print("Pinned protoc 3.21.12 and Google proto includes verified")


if __name__ == "__main__":
    install()
