"""Private parent-death guardian for one local sing-box client process."""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
from contextlib import suppress


def _stop(process: subprocess.Popen[bytes], timeout: float = 1.0) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            return
        process.wait(timeout=timeout)


def main() -> int:
    """Run sing-box until its FluxGate owner closes the control pipe or exits."""
    if len(sys.argv) != 5:
        return 64
    try:
        control_fd = int(sys.argv[1])
        lock_fd = int(sys.argv[2])
    except ValueError:
        return 64
    binary, config = sys.argv[3:]
    stopping = False

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    try:
        child = subprocess.Popen(  # noqa: S603
            [binary, "run", "-c", config],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(lock_fd,),
        )
    except OSError:
        return 70
    try:
        while child.poll() is None and not stopping:
            readable, _, _ = select.select([control_fd], [], [], 0.1)
            if readable:
                try:
                    if os.read(control_fd, 1) == b"":
                        stopping = True
                except OSError:
                    stopping = True
        if stopping:
            _stop(child)
            return 0
        return child.returncode or 0
    finally:
        with suppress(OSError):
            os.close(control_fd)
        if child.poll() is None:
            _stop(child)


if __name__ == "__main__":
    raise SystemExit(main())
