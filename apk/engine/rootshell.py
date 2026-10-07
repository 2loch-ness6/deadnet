"""
RootShell — ONE persistent ``su`` session reused for every privileged shell-out.

Why
---
Each ``subprocess.run(["su", "-c", cmd])`` forks a brand-new Magisk root shell.
On the OnePlus 12 that costs ~250 ms *per call* (measured: 40 separate ``su -c``
= 10.3 s). The finder's subnet sweep fires up to 254 of them and the mac-vacuum
re-fires one per known host every second, so the device drowns in su-fork
overhead — the "massive overhead" the owner hit.

Model (owner's spec)
--------------------
  * ONE ``su`` is opened lazily and kept alive; commands are fed over its stdin
    and results read back over its stdout. The su-fork cost is paid ONCE.
  * Stateless from the caller's side: every ``run()`` is independent (we do not
    rely on cwd / vars / exports surviving between calls).
  * Serialized: a single lock means one command is in flight at a time, so the
    shared shell can't interleave two callers' output.
  * Self-healing: if the shell has died (EOF / broken pipe) or a command wedges
    past its timeout, the shell is killed and respawned on the next call.

Protocol
--------
For each command we write::

    <cmd> 2>&1
    printf '\\n<NONCE> %s\\n' $?

and read stdout until the unique ``<NONCE> <rc>`` line. Everything before the
injected newline is the command's (merged stdout+stderr) output; the token after
the nonce is its exit code. The nonce carries a per-call counter so a command
that happens to print the marker text can't spoof completion.

Headless-safe: importing never spawns anything (the shell starts on first
``run``). The self-test drives the exact protocol against ``/bin/sh`` instead of
``su`` so it runs on the build box. Stdlib only.
"""
from __future__ import annotations

import os
import select
import subprocess
import threading
import time
from typing import List, Optional, Sequence, Tuple


class RootShell:
    """A single long-lived privileged shell. Thread-safe; lazily (re)spawned."""

    def __init__(self, shell_argv: Sequence[str] = ("su",)):
        self._argv = list(shell_argv)
        self._p: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self._ctr = 0

    # -- lifecycle ----------------------------------------------------------
    def _alive(self) -> bool:
        return self._p is not None and self._p.poll() is None

    def _spawn(self) -> None:
        # stderr is merged per-command via `2>&1`, so the session needs only the
        # one stdout pipe. bufsize=0 → unbuffered; we drive reads with select.
        self._p = subprocess.Popen(
            self._argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

    def _kill(self) -> None:
        p, self._p = self._p, None
        if p is None:
            return
        for step in (
            lambda: p.stdin and p.stdin.close(),
            p.kill,
            lambda: p.wait(timeout=2),
        ):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass

    def close(self) -> None:
        with self._lock:
            self._kill()

    # -- the one primitive --------------------------------------------------
    def run(self, cmd: str, timeout: float = 5.0) -> Tuple[int, str]:
        """Run ``cmd`` as root in the persistent shell. Returns (rc, output)
        with stdout+stderr merged. rc == -1 means the command timed out or the
        shell broke (and has been killed so the next call respawns it)."""
        with self._lock:
            if not self._alive():
                self._spawn()
            self._ctr += 1
            nonce = ("__RS_%d_%d__" % (os.getpid(), self._ctr)).encode()
            # Run inside a subshell so the command is STATELESS w.r.t. the
            # session: an `exit`, `cd`, `set`, or var assignment in `cmd` stays
            # contained and can't kill or mutate the shared shell. Cheap (a sh
            # subshell, not another su). stderr is merged onto our stdout pipe.
            payload = ("( %s ) 2>&1\nprintf '\\n%s %%s\\n' $?\n"
                       % (cmd, nonce.decode())).encode()
            try:
                self._p.stdin.write(payload)      # type: ignore[union-attr]
                self._p.stdin.flush()             # type: ignore[union-attr]
            except Exception:  # noqa: BLE001 - broken pipe => shell died
                self._kill()
                return (-1, "")

            fd = self._p.stdout.fileno()          # type: ignore[union-attr]
            buf = bytearray()
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._kill()
                    return (-1, self._before(buf, nonce))
                r, _, _ = select.select([fd], [], [], remaining)
                if not r:
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:                      # EOF: the shell exited
                    self._kill()
                    return (-1, self._before(buf, nonce))
                buf.extend(chunk)
                done = self._parse(buf, nonce)
                if done is not None:
                    return done

    # -- protocol helpers ---------------------------------------------------
    @staticmethod
    def _parse(buf: bytearray, nonce: bytes) -> Optional[Tuple[int, str]]:
        """Return (rc, output) once the full `<nonce> <rc>\\n` line is present,
        else None (keep reading)."""
        idx = buf.find(nonce)
        if idx == -1:
            return None
        nl = buf.find(b"\n", idx)
        if nl == -1:
            return None  # rc token not fully arrived yet
        rc_tok = buf[idx + len(nonce):nl].strip()
        try:
            rc = int(rc_tok)
        except ValueError:
            rc = -1
        out = bytes(buf[:idx])
        if out.endswith(b"\n"):      # drop the single newline we injected
            out = out[:-1]
        return (rc, out.decode(errors="replace"))

    @staticmethod
    def _before(buf: bytearray, nonce: bytes) -> str:
        idx = buf.find(nonce)
        raw = bytes(buf[:idx] if idx != -1 else buf)
        return raw.decode(errors="replace")


# ===========================================================================
# Process-wide singleton + conveniences. All privileged engine shell-outs go
# through this so they share the one su.
# ===========================================================================
_ROOT = RootShell(("su",))


def root() -> RootShell:
    return _ROOT


def su(cmd: str, timeout: float = 5.0) -> str:
    """Run as root, return merged stdout+stderr (``""`` on failure)."""
    return _ROOT.run(cmd, timeout)[1]


def su_rc(cmd: str, timeout: float = 5.0) -> Tuple[int, str]:
    return _ROOT.run(cmd, timeout)


def su_cp(cmd: str, timeout: float = 5.0) -> subprocess.CompletedProcess:
    """CompletedProcess shim for callers that expect subprocess.run's result.
    stdout carries the merged output; stderr is "" (merged into stdout)."""
    rc, out = _ROOT.run(cmd, timeout)
    return subprocess.CompletedProcess(args=cmd, returncode=rc,
                                       stdout=out, stderr="")


def ping_sweep(ips: Sequence[str], timeout: float = 8.0, chunk: int = 64,
               wait_ms: int = 1000) -> int:
    """Prime the kernel ARP cache for many hosts with NO per-host su fork: each
    chunk runs as a single round-trip in the persistent shell, pinging every IP
    in the chunk in parallel (`ping -c1 -W1 & ... wait`). Returns the number of
    IPs swept. IPv6 (``:``) addresses are skipped (link-local needs a scope and
    a different ping flag; the vacuum re-pings those pointlessly otherwise)."""
    targets = [ip for ip in ips if ip and ":" not in ip]
    if not targets:
        return 0
    w = max(1, int(wait_ms))
    swept = 0
    for i in range(0, len(targets), max(1, chunk)):
        batch = targets[i:i + chunk]
        body = "; ".join("ping -c1 -W1 %s >/dev/null 2>&1 &" % ip for ip in batch)
        _ROOT.run("%s wait" % body, timeout=timeout)
        swept += len(batch)
    return swept


# ---------------------------------------------------------------------------
# Self-test (build box): drive the protocol against /bin/sh (no device/root).
#   python3 engine/rootshell.py
# ---------------------------------------------------------------------------
def _selftest() -> None:
    sh = RootShell(("/bin/sh",))
    try:
        # Trailing newline is preserved on purpose: matches subprocess.run's
        # .stdout so callers (parse_neigh_table / parse_link) stay compatible.
        rc, out = sh.run("echo hello")
        assert rc == 0 and out == "hello\n", (rc, repr(out))

        rc, out = sh.run("printf 'no-newline'")
        assert rc == 0 and out == "no-newline", (rc, repr(out))

        # a real command's stderr is merged into the returned output
        rc, out = sh.run("cat /nonexistent_rs_path_xyz")
        assert rc != 0 and "o such file" in out.lower(), (rc, repr(out))

        # STATELESS: a var/cd set in one call must NOT leak into the next
        # (each runs in its own subshell), and it's the SAME session process.
        pid1 = sh._p.pid
        sh.run("FOO=bar; cd /tmp")
        rc, out = sh.run("echo ${FOO:-unset}")
        assert rc == 0 and out == "unset\n", (rc, repr(out))
        assert sh._p.pid == pid1, "session must be reused across calls"

        # an `exit` inside a command must not kill the session
        rc, out = sh.run("exit 7")
        assert rc == 7, (rc, repr(out))
        assert sh._alive() and sh._p.pid == pid1, "exit must stay in subshell"

        # multi-line / piped command
        rc, out = sh.run("printf 'a\\nb\\nc\\n' | grep -c b")
        assert rc == 0 and out == "1\n", (rc, repr(out))

        # a command that prints nonce-looking text must not spoof completion
        rc, out = sh.run("echo __RS_fake__ 0")
        assert rc == 0 and out == "__RS_fake__ 0\n", (rc, repr(out))

        # timeout kills + respawns; next call works on a fresh shell
        rc, out = sh.run("sleep 5", timeout=0.4)
        assert rc == -1, (rc, out)
        assert not sh._alive(), "shell must be dead after timeout"
        rc, out = sh.run("echo back")
        assert rc == 0 and out == "back\n", (rc, out)
        assert sh._p.pid != pid1, "shell should have respawned"

        # ping_sweep against the singleton would need su; just exercise the IPv6
        # filter / chunking math on the module helper with a stubbed shell.
        calls = []
        orig = _ROOT.run
        _ROOT.run = lambda c, timeout=8.0: calls.append(c) or (0, "")
        try:
            n = ping_sweep(["192.168.1.%d" % i for i in range(1, 70)]
                           + ["fe80::1"], chunk=64)
        finally:
            _ROOT.run = orig
        assert n == 69, n                      # IPv6 skipped, 69 IPv4 swept
        assert len(calls) == 2, len(calls)     # 69 / 64 -> 2 chunks
        assert "fe80" not in "".join(calls)
    finally:
        sh.close()
    print("rootshell PASS")


if __name__ == "__main__":
    _selftest()
