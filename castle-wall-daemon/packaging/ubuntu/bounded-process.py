"""Bounded subprocess capture shared by archive readers and install-only hooks."""
import os
import selectors
import signal
import subprocess
import time
import sys


def bounded_capture(argv, *, timeout, limit, env=None):
    # Drain both streams with a combined cap before allocation; a subprocess
    # timeout alone does not bound a malicious or broken probe's output memory.
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=env, start_new_session=True)
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 0)
            selector.register(child.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('probe capture deadline exceeded')
                for key, _ in selector.select(remaining):
                    # One extra byte establishes overflow without retaining
                    # more than limit+1 bytes across the two streams.
                    room = limit + 1 - sum(map(len, output))
                    chunk = os.read(key.fileobj.fileno(), min(64 * 1024, room))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        if sum(map(len, output)) > limit:
                            raise ValueError('probe capture output cap exceeded')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('probe capture deadline exceeded')
            if hasattr(os, 'waitid'):
                # Linux hooks keep the exited leader unreaped until group
                # cleanup, so a recycled PID cannot name an unrelated group.
                while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('probe capture deadline exceeded')
                    time.sleep(min(0.01, remaining))  # Ten-millisecond readiness polling budget.
            else:
                # Portable local tests lack waitid; success with both pipes
                # closed needs no process-group signal after the child is reaped.
                child.wait(timeout=remaining)
    finally:
        # A probe may leave a descendant holding a pipe after its parent
        # exits. The process group, not only the immediate PID, is reaped.
        if child.returncode is None:
            try:
                if sys.platform == 'linux':
                    os.killpg(child.pid, signal.SIGKILL)
                elif child.poll() is None:
                    # Non-Linux runs exercise parser tests only; macOS's
                    # managed sandbox denies killpg. Production is Linux.
                    child.kill()
            except ProcessLookupError:
                pass
        # A task in uninterruptible kernel sleep may ignore SIGKILL. The hook
        # must release dpkg's lock within a finite reap allowance and refuse.
        try:
            child.wait(timeout=1)  # One second beyond the observation deadline.
        finally:
            child.stdout.close()
            child.stderr.close()
    return child.returncode, bytes(output[0]), bytes(output[1])
