"""
Test that debugserver does not stop itself when a packet that needs a process
is handled after a detach.

After a 'D', debugserver has no process but still handles a packet that was
queued behind it. A second 'D', a 'k' or a 'C' with a signal then sent a
signal to process ID 0, that is, to debugserver's own process group. 'D' and
'k' send SIGSTOP, as does the 'C' here, so debugserver stopped itself. A 'k'
also marked the cleared process as running again, which could keep debugserver
connected until the client closed the connection. The pipelined tests send
both packets in a single write, so the second one is always queued.

The inferior is only checked to not have exited, not to be running: a detach
can occasionally leave it stopped, which is a separate bug.
"""

import re
import select
import subprocess
import time

import gdbremote_testcase
from lldbsuite.test.decorators import *


@requireDarwin
@skipIfMTE  # MTE security transition shims restrict socket operations.
@skipIfOutOfTreeDebugserver
@skipIfRemote  # Uses the host's ps and polls local processes.
class TestGdbRemoteDetachTwice(gdbremote_testcase.GdbRemoteTestCaseBase):
    # How long debugserver may take to send its replies, and to exit once the
    # client has closed the connection.
    WATCH_TIMEOUT_S = 15
    WATCH_INTERVAL_S = 0.1
    # How long debugserver may take to reply to a 'k' queued behind a 'D' and
    # then close the connection or exit by itself.
    KILL_CLOSE_TIMEOUT_S = 5

    def attach(self):
        """Attach debugserver to a new inferior with vAttach and return the
        processes."""
        self.build()
        self.set_inferior_startup_attach_manually()
        # The inferior outlives every check below.
        procs = self.prep_debug_monitor_and_inferior(inferior_args=["sleep:120"])
        self.test_sequence.add_log_lines(
            [
                "read packet: $vAttach;{:x}#00".format(procs["inferior"].pid),
                {
                    "direction": "send",
                    "regex": r"^\$T[0-9a-fA-F]{2}[^#]*#[0-9a-fA-F]{2}$",
                },
            ],
            True,
        )
        self.expect_gdbremote_sequence()
        return procs

    def watch_server(self, server, done, timeout):
        """Call done() every WATCH_INTERVAL_S until it returns True, for at
        most timeout seconds, and return whether it did. Fail at once if ps
        shows the server stopped."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            stat = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(server.pid)],
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertNotIn(
                "T",
                stat,
                "debugserver (pid %d) is stopped (ps state %s)" % (server.pid, stat),
            )
            if done():
                return True
            time.sleep(self.WATCH_INTERVAL_S)
        return False

    def check_replies(self, server, expected, timeout):
        """Read replies until the server closes its end of the connection, for
        at most timeout seconds, and check that their payloads are exactly the
        expected ones. Return whether the server closed its end.

        A server that exits closes its end too. Reading on to the end of the
        stream, instead of stopping once the process is gone, keeps replies
        that are still in flight when it exits.

        Reads use select() with a zero timeout, so a stopped server cannot
        hang the test; the framework's blocking reads are not used. Checksums
        are not checked: debugserver sends #00 in no-ack mode."""
        received = bytearray()

        def server_closed():
            while select.select([self.sock], [], [], 0)[0]:
                data = self.sock.recv(4096)
                if not data:
                    return True
                received.extend(data)
            return False

        closed = self.watch_server(server, server_closed, timeout)
        payloads = re.findall(rb"\$([^#]*)#[0-9a-fA-F]{2}", bytes(received))
        self.assertEqual(payloads, expected, "debugserver sent %r" % bytes(received))
        return closed

    def check_exit_after_close(self, procs):
        """Close the connection, then check that debugserver exits and that
        the inferior has not exited."""
        server = procs["server"]
        self.sock.close()
        self.assertTrue(
            self.watch_server(
                server, lambda: server.poll() is not None, self.WATCH_TIMEOUT_S
            ),
            "debugserver did not exit within %d s of the connection closing"
            % self.WATCH_TIMEOUT_S,
        )
        self.assertIsNone(
            procs["inferior"].poll(), "the inferior exited after the detach"
        )

    @add_test_categories(["debugserver"])
    def test_detach_twice(self):
        """A second 'D' queued behind the first gets an error reply."""
        procs = self.attach()
        self._server.send_raw(b"$D#44$D#44")
        self.check_replies(procs["server"], [b"OK", b"E01"], self.WATCH_TIMEOUT_S)
        self.check_exit_after_close(procs)

    @add_test_categories(["debugserver"])
    def test_kill_after_detach(self):
        """A 'k' queued behind a 'D' gets its usual reply, and debugserver
        then closes the connection or exits by itself, before the client
        closes it."""
        procs = self.attach()
        self._server.send_raw(b"$D#44$k#6b")
        self.assertTrue(
            self.check_replies(
                procs["server"], [b"OK", b"X09"], self.KILL_CLOSE_TIMEOUT_S
            ),
            "debugserver did not close the connection or exit by itself within "
            "%d s of the 'k'" % self.KILL_CLOSE_TIMEOUT_S,
        )
        self.check_exit_after_close(procs)

    @add_test_categories(["debugserver"])
    def test_signal_after_detach(self):
        """A 'C' with a signal, queued behind a 'D', gets an error reply."""
        procs = self.attach()
        # C11 continues with signal 0x11, which is SIGSTOP on Darwin.
        self._server.send_raw(b"$D#44$C11#a5")
        self.check_replies(procs["server"], [b"OK", b"E52"], self.WATCH_TIMEOUT_S)
        self.check_exit_after_close(procs)

    @add_test_categories(["debugserver"])
    def test_detach_then_disconnect(self):
        """Close the connection right after a 'D'.

        This catches a race: if debugserver sees the connection close before
        it exits after the detach, it detaches a second time on its way out.
        Closing right after the 'D' makes that order likely."""
        procs = self.attach()
        self._server.send_raw(b"$D#44")
        self.check_exit_after_close(procs)
