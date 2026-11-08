"""Linux supervisor for one local, digest-bound CPU evaluation at a time."""

import math
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

_KEY_MAX = 64 << 20
_PAIR_MAX = 2 * (8 + (1 << 20))
_CHUNK = 256 << 10
_PRLIMIT = "/usr/bin/prlimit"
_SLOT = threading.BoundedSemaphore(1)


class Failure(StrEnum):
    INPUT = "RUNNER_INPUT"
    BUSY = "RUNNER_BUSY"
    UNAVAILABLE = "RUNNER_UNAVAILABLE"
    TIMEOUT = "RUNNER_TIMEOUT"
    RESOURCE = "RUNNER_RESOURCE"
    REJECTED = "RUNNER_REJECTED"
    CHILD_DIED = "RUNNER_CHILD_DIED"
    OUTPUT = "RUNNER_OUTPUT"


class RunnerError(RuntimeError):
    def __init__(self, failure: Failure):
        self.failure = failure
        super().__init__(failure.value)


@dataclass(frozen=True, slots=True)
class Limits:
    """Trusted launcher policy. Callers may lower the standard per-job limits."""

    wall_seconds: float = 20
    cpu_seconds: int = 16
    address_space_bytes: int = 2 << 30

    def __post_init__(self):
        if (
            not 0 < self.wall_seconds <= 20
            or type(self.cpu_seconds) is not int
            or not 1 <= self.cpu_seconds <= 16
            or type(self.address_space_bytes) is not int
            or not 1 <= self.address_space_bytes <= 2 << 30
        ):
            raise ValueError("RUNNER_POLICY")


@dataclass(frozen=True, slots=True)
class EvaluationRequest:
    key: Path
    input: Path
    evaluation_key_digest: str
    input_blob_digest: str
    program_digest: str


def _open_bounded(path: Path, limit: int):
    # Reject symlinks, special files and sparse oversize files before reading.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("RUNNER_FILE")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _stage(source: Path, destination: Path, limit: int) -> None:
    with _open_bounded(source, limit) as stream, destination.open("xb") as target:
        remaining = limit
        while chunk := stream.read(min(_CHUNK, remaining + 1)):
            if len(chunk) > remaining:
                raise ValueError("RUNNER_FILE")
            target.write(chunk)
            remaining -= len(chunk)
        if remaining == limit:
            raise ValueError("RUNNER_FILE")


def _run(worker: Path, scratch: Path, request: EvaluationRequest, limits: Limits) -> None:
    child = subprocess.Popen(
        [
            _PRLIMIT,
            f"--as={limits.address_space_bytes}:{limits.address_space_bytes}",
            f"--cpu={limits.cpu_seconds}:{limits.cpu_seconds + 1}",
            "--core=0:0",
            f"--fsize={_PAIR_MAX}:{_PAIR_MAX}",
            "--nofile=32:32",
            "--",
            str(worker),
            "evaluate",
            "evaluation.bin",
            "input.bin",
            "output.bin",
            request.evaluation_key_digest,
            request.input_blob_digest,
            request.program_digest,
        ],
        cwd=scratch,
        env={"HOME": str(scratch), "TMPDIR": str(scratch), "RAYON_NUM_THREADS": "2", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    try:
        fd = os.pidfd_open(child.pid)
        try:
            poll = select.poll()
            poll.register(fd, select.POLLIN)
            if not poll.poll(math.ceil(limits.wall_seconds * 1000)):
                raise RunnerError(Failure.TIMEOUT)
        finally:
            os.close(fd)
    finally:
        # The pidfd reports exit without reaping. Kill descendants before
        # releasing the leader's PID, even if the leader exited normally.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            status = child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise RunnerError(Failure.CHILD_DIED) from None

    if status in (-signal.SIGXCPU, -signal.SIGXFSZ):
        raise RunnerError(Failure.RESOURCE)
    if status == 2:
        raise RunnerError(Failure.REJECTED)
    if status != 0:
        raise RunnerError(Failure.CHILD_DIED)


_DEFAULT_LIMITS = Limits()


def run_evaluation(
    worker: Path,
    request: EvaluationRequest,
    *,
    scratch_root: Path | None = None,
    limits: Limits = _DEFAULT_LIMITS,
) -> bytes:
    """Run the trusted worker using local artifact paths and approved commitments."""
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        raise RunnerError(Failure.UNAVAILABLE)
    if not all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (
            request.evaluation_key_digest,
            request.input_blob_digest,
            request.program_digest,
        )
    ):
        raise RunnerError(Failure.INPUT)
    if not _SLOT.acquire(blocking=False):
        raise RunnerError(Failure.BUSY)
    try:
        with tempfile.TemporaryDirectory(prefix="cpu-eval-", dir=scratch_root) as directory:
            scratch = Path(directory).absolute()
            try:
                _stage(request.key, scratch / "evaluation.bin", _KEY_MAX)
                _stage(request.input, scratch / "input.bin", _PAIR_MAX)
            except OSError, ValueError:
                raise RunnerError(Failure.INPUT) from None

            _run(worker.resolve(), scratch, request, limits)
            try:
                with _open_bounded(scratch / "output.bin", _PAIR_MAX) as stream:
                    output = stream.read(_PAIR_MAX + 1)
                if not 0 < len(output) <= _PAIR_MAX:
                    raise ValueError("RUNNER_FILE")
            except OSError, ValueError:
                raise RunnerError(Failure.OUTPUT) from None
            return output
    except OSError:
        raise RunnerError(Failure.UNAVAILABLE) from None
    finally:
        _SLOT.release()
