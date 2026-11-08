import os
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from tools.cpu_runner import EvaluationRequest, Failure, Limits, RunnerError, run_evaluation

DIGEST = "a" * 64


class RunnerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.key = self.root / "key"
        self.key.write_bytes(b"public")
        self.input = self.root / "input"
        self.input.write_bytes(b"ciphertext")
        self.worker = self.root / "worker"
        self.request = EvaluationRequest(self.key, self.input, DIGEST, DIGEST, DIGEST)

    def invoke(self, script, **kwargs):
        self.worker.write_text(f"#!{sys.executable}\n" + script, encoding="utf-8")
        self.worker.chmod(0o700)
        try:
            return run_evaluation(self.worker, self.request, scratch_root=self.scratch, **kwargs)
        finally:
            self.assertEqual(list(self.scratch.iterdir()), [])

    def test_minimal_environment_no_core_and_bounded_output(self):
        with patch.dict(os.environ, {"PRIVATE_MARKER": "test-only"}):
            self.assertEqual(
                self.invoke(
                    "import os, resource, sys\n"
                    "assert 'PRIVATE_MARKER' not in os.environ\n"
                    "assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)\n"
                    "os.write(1, b'x' * (4 << 20))\n"
                    "os.write(2, b'x' * (4 << 20))\n"
                    "open(sys.argv[4], 'wb').write(b'result')\n"
                ),
                b"result",
            )

    def test_timeout_kills_descendants_and_cleans_scratch(self):
        marker = self.root / "survived"
        started = self.root / "started"
        with self.assertRaises(RunnerError) as failure:
            self.invoke(
                "import os, time\n"
                "if os.fork() == 0:\n"
                f"    open({str(started)!r}, 'w').close()\n"
                "    time.sleep(1.5)\n"
                f"    open({str(marker)!r}, 'w').close()\n"
                "time.sleep(30)\n",
                limits=Limits(wall_seconds=1),
            )
        self.assertEqual(failure.exception.failure, Failure.TIMEOUT)
        self.assertTrue(started.exists())
        time.sleep(1)
        self.assertFalse(marker.exists())

    def test_resource_and_unexpected_child_death_are_typed(self):
        scripts = (
            ("import os, signal\nos.kill(os.getpid(), signal.SIGSEGV)\n", Failure.CHILD_DIED),
            ("import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n", Failure.CHILD_DIED),
            ("while True: pass\n", Failure.RESOURCE),
            (
                "import signal, sys\nsignal.signal(signal.SIGXFSZ, signal.SIG_DFL)\n"
                "with open(sys.argv[4], 'wb') as out: out.write(b'x' * (4 << 20))\n",
                Failure.RESOURCE,
            ),
        )
        for script, expected in scripts:
            with self.subTest(expected=expected), self.assertRaises(RunnerError) as failure:
                self.invoke(script, limits=Limits(cpu_seconds=1, wall_seconds=5))
            self.assertEqual(failure.exception.failure, expected)

    def test_address_space_limit_is_enforced(self):
        with self.assertRaises(RunnerError) as failure:
            self.invoke(
                "import os, resource\n"
                "assert resource.getrlimit(resource.RLIMIT_AS) == (64 << 20, 64 << 20)\n"
                "try:\n"
                "    bytearray(128 << 20)\n"
                "except MemoryError:\n"
                "    os.abort()\n",
                limits=Limits(address_space_bytes=64 << 20),
            )
        self.assertEqual(failure.exception.failure, Failure.CHILD_DIED)

    def test_concurrent_request_does_not_start_another_worker(self):
        started = self.root / "running"
        finish = self.root / "finish"
        script = (
            "import os, sys, time\n"
            f"open({str(started)!r}, 'w').close()\n"
            f"while not os.path.exists({str(finish)!r}): time.sleep(0.01)\n"
            "open(sys.argv[4], 'wb').write(b'result')\n"
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            job = executor.submit(self.invoke, script)
            try:
                deadline = time.monotonic() + 5
                while not started.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(started.exists())
                with self.assertRaises(RunnerError) as failure:
                    run_evaluation(self.worker, self.request, scratch_root=self.scratch)
                self.assertEqual(failure.exception.failure, Failure.BUSY)
            finally:
                finish.touch()
            self.assertEqual(job.result(timeout=5), b"result")

    def test_worker_cannot_return_a_symlink_or_missing_output(self):
        for script in (
            "pass\n",
            "import os, sys\nos.symlink(sys.argv[3], sys.argv[4])\n",
        ):
            with self.assertRaises(RunnerError) as failure:
                self.invoke(script)
            self.assertEqual(failure.exception.failure, Failure.OUTPUT)

    def test_hostile_artifact_paths_and_lengths_reject_before_spawn(self):
        self.input.unlink()
        os.mkfifo(self.input)
        with self.assertRaises(RunnerError) as failure:
            self.invoke("raise AssertionError('should not spawn')\n")
        self.assertEqual(failure.exception.failure, Failure.INPUT)
        self.input.unlink()
        with self.input.open("wb") as stream:
            stream.truncate(4 << 20)
        with self.assertRaises(RunnerError) as failure:
            self.invoke("raise AssertionError('should not spawn')\n")
        self.assertEqual(failure.exception.failure, Failure.INPUT)
