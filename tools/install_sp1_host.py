"""GitHub Ubuntu runner setup: bypass Azure mirror DNS without changing the OS."""

import subprocess
from pathlib import Path

MIRRORS = Path("/etc/apt/apt-mirrors.txt")


def install(mirrors: Path = MIRRORS) -> None:
    rows = mirrors.read_text().splitlines(keepends=True)
    remaining = [row for row in rows if "azure.archive.ubuntu.com" not in row]
    if not any(row.startswith("https://archive.ubuntu.com/ubuntu/") for row in remaining):
        raise ValueError("OFFICIAL_UBUNTU_MIRROR_REQUIRED")
    mirrors.write_text("".join(remaining))
    options = [
        "-o",
        "Acquire::Retries=3",
        "-o",
        "Acquire::http::Timeout=20",
        "-o",
        "Acquire::https::Timeout=20",
    ]
    subprocess.run(
        ["apt-get", *options, "-o", "APT::Update::Error-Mode=any", "update"],
        check=True,
        timeout=180,
    )
    subprocess.run(
        [
            "apt-get",
            *options,
            "install",
            "--yes",
            "--no-install-recommends",
            "protobuf-compiler",
            "libprotobuf-dev",
        ],
        check=True,
        timeout=180,
    )
    subprocess.run(["protoc", "--version"], check=True, timeout=10)


if __name__ == "__main__":
    install()
