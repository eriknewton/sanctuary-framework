"""Bounded subprocess capture shared by archive readers and install-only hooks."""
import os
import selectors
import signal
import subprocess
import time


def bounded_capture(argv, *, timeout, limit, env=None):
    # Drain both streams with a combined cap before allocation; a subprocess
    # timeout alone does not bound a malicious or broken probe's output memory.
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=env, start_new_session=True) as child:
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
                status = child.wait(timeout=remaining)
            return status, bytes(output[0]), bytes(output[1])
        finally:
            # A probe may leave a descendant holding a pipe after its parent
            # exits. The process group, not only the immediate PID, is reaped.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
