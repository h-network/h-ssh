"""#127: the probe. Before every run, and alone with --probe, each box is
asked at the protocol level whether it is there, without logging in: a TCP
connect, the server's first line checked to be an SSH banner, the
connection closed. A dead box is a FAIL of the run within seconds; an edit
goes on without one only when the operator says so. Listeners on localhost
stand in for the boxes (`real_probe`); elsewhere the probe's tries are
answered here and the drivers are fakes in drivers.MODULES."""

import asyncio
import contextlib
import errno
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import sys
import threading
import time
import types

import pytest

from hssh import Fleet, cli, drivers, limits, probe
from hssh.core import Target
from hssh.store import main as store_main
from tests.test_time_bounds import _full_listener
from tests.test_transport_consistency import _rlimits

BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"


class Box:
    """A listener on 127.0.0.1 standing in for a box: every connection gets
    `says` at once (a banner, another server's greeting, nothing), then is
    closed, or held open without another word when `hold`."""

    def __init__(self, says=b"", hold=False):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.held = []
        threading.Thread(target=self._serve, args=(says, hold), daemon=True).start()

    def _serve(self, says, hold):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            if says:
                conn.sendall(says)
            if hold:
                self.held.append(conn)
            else:
                conn.close()

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)       # wakes the accept on Linux
        except OSError:
            pass
        self.sock.close()
        for conn in self.held:
            conn.close()


@pytest.fixture
def boxes(real_probe, monkeypatch):
    """Box(...) makes one; every one is closed after the test. The pause
    before a second try is cut to 50 ms."""
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0.05)
    made = []

    def make(says=b"", hold=False):
        made.append(Box(says, hold))
        return made[-1]
    yield make
    for box in made:
        box.close()


def refused_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def answering(dead=(), slow=(), silent=(), seen=None):
    """An attempt() for the probe to call instead of the network: a host in
    `dead` refuses, one in `silent` accepts and says nothing, one in `slow`
    answers live at 10.7 ms, every other live at 0.4 ms. `seen` gets the
    (host, port) of every try."""
    async def attempt(host, port, banner, seconds):
        if seen is not None:
            seen.append((host, port))
        if host in dead:
            return probe.Answer(probe.REFUSED, f"connection refused by {host}:{port}")
        if host in silent:
            return probe.Answer(probe.SILENT, f"no SSH banner from {host}:{port} within {seconds:g}s", 0.4)
        if banner is None:
            return probe.Answer(probe.LIVE, connect_ms=0.4)
        if host in slow:
            return probe.Answer(probe.LIVE, None, 10.7, 16.5, "SSH-2.0-OpenSSH_9.6")
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-OpenSSH_9.6")
    return attempt


class Junos:
    """A fake junos@netconf module: every call recorded, every call fine."""
    AVAILABLE = True

    def __init__(self):
        self.calls = []

    def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, **kw):
        self.calls.append(("show", host))
        return f"{cmd} on {host}\n"

    def show_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None, **kw):
        self.calls.append(("show_batch", host))
        return [{"command": c, "ok": True, "output": f"{c} on {host}"} for c in cmds]

    def edit(self, host, user, passwd, payload, st, ct, commit_confirmed=None, port=None, vendor_hint=None,
             dry_run=False, comment=None, expected_diff=None, **kw):
        self.calls.append(("dry-run" if dry_run else "edit", host))
        verdict = "DRY-RUN: commit check passed, nothing committed" if dry_run else "COMMIT OK"
        return f"{verdict}\n\nDIFF:\n[edit system]\n+   host-name x;\n"

    def rollback(self, host, user, passwd, n, st, ct, port=None, vendor_hint=None, dry_run=False,
                 commit_confirmed=None, **kw):
        self.calls.append(("rollback", host))
        return "COMMIT OK\n"

    def commit_status(self, host, user, passwd, st, ct, port=None, vendor_hint=None, **kw):
        self.calls.append(("commit_status", host))
        return []


def run(monkeypatch, capsys, argv, driver=None, tty=False, answer=None, config=os.devnull, password="p"):
    """h-ssh main() in this process against the fake junos driver. `tty`:
    whether stdin and stdout are terminals; `answer`: what the operator
    types at a question (None: a question fails the test). Returns (rc,
    stdout, stderr, the questions asked, the driver)."""
    driver = driver or Junos()
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    if password is not None:
        monkeypatch.setenv("HSSH_PASSWORD", password)
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0)
    monkeypatch.setattr(cli, "_tty", lambda stream: tty)
    asked = []

    def ask(prompt, secret=False):
        asked.append(prompt)
        if answer is None:
            raise AssertionError(f"asked {prompt!r}")
        return answer
    monkeypatch.setattr(cli, "_ask", ask)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", config, "--user", "u", *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err, asked, driver


def rows(sql, *params):
    con = sqlite3.connect(os.environ["HSSH_STORE"])
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, params).fetchall()]
    finally:
        con.close()


R12 = ["R1:10.0.0.1:junos", "R2:10.0.0.2:junos"]


# --- the probe itself, against boxes on localhost ------------------------------------

def test_each_kind_of_box_gets_its_result_and_reason(boxes):
    """Live with sshd's version string; silent (TCP accepted, no banner in
    time, or the connection closed without one: #44, a port that accepts
    and closes is not a device); not SSH; refused; a name that does not
    resolve; and telnet, which has no banner: a TCP connect alone."""
    live, held, web, closes = boxes(BANNER), boxes(hold=True), boxes(b"HTTP/1.1 400 Bad Request\r\n\r\n"), boxes()
    dead = refused_port()
    targets = [Target("R1", "127.0.0.1", "junos", live.port), Target("R2", "127.0.0.1", "ssh", held.port),
               Target("R3", "127.0.0.1", "openssh", web.port), Target("R4", "127.0.0.1", "ssh", closes.port),
               Target("R5", "127.0.0.1", "ssh", dead), Target("R6", "no-such-host.invalid", "ssh"),
               Target("SW", "127.0.0.1", "telnet-ios", closes.port)]
    started = time.monotonic()
    got = asyncio.run(probe.probe(targets, 1))
    took = time.monotonic() - started
    assert [r.device for r in got] == ["R1", "R2", "R3", "R4", "R5", "R6", "SW"]       # the targets' order
    assert [r.result for r in got] == ["live", "silent", "not SSH", "silent", "refused", "name not found", "live"]
    r1 = got[0]
    assert r1.ok and r1.banner == "SSH-2.0-OpenSSH_9.6" and r1.reason is None and r1.slow is None
    assert r1.connect_ms is not None and 0 <= r1.connect_ms < 100 and r1.banner_ms is not None
    assert (r1.host, r1.port, r1.vendor) == ("127.0.0.1", live.port, "junos")
    assert got[1].reason == f"no SSH banner from 127.0.0.1:{held.port} within 1s" and got[1].connect_ms is not None
    assert got[2].reason == f"127.0.0.1:{web.port} answered 'HTTP/1.1 400 Bad Request', not an SSH banner"
    assert got[3].reason == f"127.0.0.1:{closes.port} closed the connection without an SSH banner"
    assert got[4].reason == f"connection refused by 127.0.0.1:{dead}" and got[4].connect_ms is None
    assert got[5].reason.startswith(("cannot resolve no-such-host.invalid", "name lookup for no-such-host.invalid"))
    sw = got[6]
    assert sw.ok and sw.banner is None and sw.banner_ms is None and sw.connect_ms is not None
    assert [r.ok for r in got] == [True, False, False, False, False, False, True]
    assert [r.dead for r in got] == [False, True, True, True, True, True, False]
    assert got[4].verdict == f"refused (connection refused by 127.0.0.1:{dead})" and r1.verdict == "live"
    # the silent box waited 1 s twice, the pause between; the others were not held up by it
    assert 2.0 <= took < 5.0 and got[1].duration_ms >= 2000 and got[0].duration_ms < 1000


def test_a_box_that_does_not_answer_the_tcp_connect_times_out(real_probe, monkeypatch):
    """As a blackholed address: a port whose accept queue is full drops the
    SYN, so the connect gets no answer at all, twice."""
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0.05)
    held, port = _full_listener()
    try:
        started = time.monotonic()
        r, = asyncio.run(probe.probe([Target("R9", "127.0.0.1", "ssh", port)], 1))
        took = time.monotonic() - started
    finally:
        for s in held:
            s.close()
    assert (r.result, r.reason, r.connect_ms) == ("timed out", f"TCP connect to 127.0.0.1:{port} timed out after 1s",
                                                  None)
    assert 2.0 <= took < 5.0


def test_lines_before_the_ssh_line_are_passed_over_as_the_ssh_clients_pass_them(boxes):
    """RFC 4253 lets a server send other lines before its identification
    line, and paramiko and OpenSSH take them, so the probe does too: up to
    100 lines in all, as paramiko reads them, 255 bytes each. Something
    else on the port is still not SSH, whether it closes or waits for the
    client after its greeting."""
    greets, blank = boxes(b"Welcome to the box\r\n" + BANNER), boxes(b"\r\n" + BANNER)
    ninety_nine = boxes(b"".join(b"line %d\r\n" % i for i in range(99)) + BANNER)       # the banner the 100th line
    hundred = boxes(b"".join(b"line %d\r\n" % i for i in range(100)) + BANNER)          # ... and the 101st
    smtp = boxes(b"220 mail.example ESMTP\r\n", hold=True)
    long = boxes(b"x" * 300 + b"\r\n" + BANNER)
    bits = boxes(b"SSH-2.0-Open", hold=True)                                         # sshd stuck in its banner
    made = (greets, blank, ninety_nine, hundred, smtp, long, bits)
    got = asyncio.run(probe.probe([Target(f"R{i}", "127.0.0.1", "ssh", b.port) for i, b in enumerate(made, 1)], 1))
    assert [r.result for r in got] == ["live", "live", "live", "not SSH", "not SSH", "not SSH", "silent"]
    assert got[0].banner == got[1].banner == got[2].banner == "SSH-2.0-OpenSSH_9.6" and got[0].banner_ms is not None
    assert got[3].reason == f"127.0.0.1:{hundred.port} answered 'line 0', not an SSH banner"
    assert got[4].reason == f"127.0.0.1:{smtp.port} answered '220 mail.example ESMTP', not an SSH banner"
    assert got[5].reason == f"127.0.0.1:{long.port} answered {'x' * 40 + '…'!r}, not an SSH banner"
    assert got[6].reason == f"no SSH banner from 127.0.0.1:{bits.port} within 1s"


def test_a_name_no_resolver_takes_is_name_not_found_and_the_rest_are_probed(real_probe, monkeypatch):
    """`10.0.0..1` (an empty label; one over 63 characters the same) makes
    getaddrinfo raise UnicodeError, not gaierror: the box is name not
    found, with the reason, and every other box is probed as usual."""
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0)
    got = asyncio.run(probe.probe([Target("R1", "10.0.0..1", "ssh"), Target("R2", "a" * 64 + ".example", "ssh"),
                                   Target("R3", "127.0.0.1", "ssh", refused_port())], 1))
    assert [r.result for r in got] == ["name not found", "name not found", "refused"]
    assert got[0].reason.startswith("cannot resolve 10.0.0..1: label empty")       # the codec's words, whatever Python
    assert got[1].reason.startswith("cannot resolve aaaa") and got[1].reason.endswith("too long")
    wrapped = UnicodeError("encoding with 'idna' codec failed (UnicodeError: label empty or too long)")  # 3.10's
    assert probe._codec_words(wrapped) == "label empty or too long"
    assert probe._codec_words(UnicodeEncodeError("idna", "10.0.0..1", 6, 7, "label empty")) == "label empty"


def test_a_surprise_in_one_boxs_probe_is_that_boxs_error_and_the_others_go_on(monkeypatch, capsys):
    """Anything the probe did not expect is the box's own result, error, a
    dead box with the exception in its reason, and never the end of the
    whole fleet's probe or run."""
    async def attempt(host, port, banner, seconds):
        if host == "10.0.0.2":
            raise RuntimeError("a bug")
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-OpenSSH_9.6")
    monkeypatch.setattr(probe, "attempt", attempt)
    got = asyncio.run(probe.probe([Target("R1", "10.0.0.1", "junos"), Target("R2", "10.0.0.2", "junos")], 3))
    assert [(r.result, r.dead) for r in got] == [("live", False), ("error", True)]
    assert got[1].reason == "the probe of 10.0.0.2:830 failed: RuntimeError: a bug"
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", *R12])
    assert rc == 1 and driver.calls == [("show", "10.0.0.1")]
    assert ": 1 live, 1 dead (error 1)" in out
    assert "R2               FAIL\n  ERROR: probe: error (the probe of 10.0.0.2:830 failed: RuntimeError: a bug)" in out


def test_a_box_that_fails_is_tried_once_more_after_a_pause(monkeypatch):
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0.2)
    tries = {}

    async def attempt(host, port, banner, seconds):
        tries.setdefault(host, []).append(time.monotonic())
        if host == "10.0.0.1" and len(tries[host]) == 1:
            return probe.Answer(probe.TIMED_OUT, f"TCP connect to {host}:22 timed out after 3s")
        if host == "10.0.0.2":
            return probe.Answer(probe.REFUSED, f"connection refused by {host}:22 (try {len(tries[host])})")
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-x")
    monkeypatch.setattr(probe, "attempt", attempt)
    got = asyncio.run(probe.probe([Target(f"R{i}", f"10.0.0.{i}", "ssh") for i in (1, 2, 3)], 3))
    assert [r.result for r in got] == ["live", "refused", "live"]
    assert got[1].reason == "connection refused by 10.0.0.2:22 (try 2)"          # the second try's words stand
    assert {h: len(t) for h, t in tries.items()} == {"10.0.0.1": 2, "10.0.0.2": 2, "10.0.0.3": 1}
    assert all(t[1] - t[0] >= 0.19 for t in tries.values() if len(t) == 2)       # after the pause


def test_at_most_100_boxes_are_probed_at_once(monkeypatch):
    state = {"now": 0, "peak": 0}

    async def attempt(host, port, banner, seconds):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.2)
        state["now"] -= 1
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-x")
    monkeypatch.setattr(probe, "attempt", attempt)
    targets = [Target(f"R{i}", f"10.0.{i // 250}.{i % 250 + 1}", "ssh") for i in range(250)]
    got = asyncio.run(probe.probe(targets, 3))
    assert len(got) == 250 and all(r.ok for r in got)
    assert limits.MAX_PROBES == probe.MAX_PROBES == 100 and state["peak"] == 100
    state["peak"] = 0
    asyncio.run(probe.probe(targets[:30], 3, limit=7))
    assert state["peak"] == 7


def test_the_probes_at_once_are_fitted_to_the_open_file_limit(monkeypatch, capsys):
    """A probe holds one descriptor; the soft limit is raised first, as for
    the workers, and only what is still short lowers the probes at once,
    with one warning. A run needs no more probes than it has boxes."""
    _rlimits(monkeypatch, 64, 64, settable=False)
    assert limits.fit_probes_to_open_files(100) == (32, "the open-file limit of 64 (ulimit -n) carries 32 probes "
                                                        "at once, not 100; probing 32 at a time")
    assert limits.fit_probes_to_open_files(20) == (20, None)
    state = _rlimits(monkeypatch, 1024, 65536)
    assert limits.fit_probes_to_open_files(100) == (100, None) and state["set"] == []
    _rlimits(monkeypatch, 64, 64, settable=False)
    state = {"now": 0, "peak": 0}

    async def attempt(host, port, banner, seconds):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.2)
        state["now"] -= 1
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-x")
    monkeypatch.setattr(probe, "attempt", attempt)
    targets = [f"R{i}:10.0.0.{i + 1}:junos" for i in range(40)]
    rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", "--workers", "1", *targets])
    assert rc == 0, err
    assert err.count("WARNING: the open-file limit of 64 (ulimit -n) carries 32 probes at once, not 40; "
                     "probing 32 at a time") == 1
    assert state["peak"] == 32


def tcp_info(rtt_us):
    """struct tcp_info as the kernel fills it, tcpi_rtt at byte offset 68."""
    return bytes(68) + struct.pack("=I", rtt_us) + bytes(104 - 72)


def kernel_says(monkeypatch, rtt_us=None, refuse=False):
    """getsockopt(IPPROTO_TCP, TCP_INFO) answered here: tcpi_rtt = rtt_us, or
    ENOPROTOOPT when `refuse`; every other option as the kernel answers."""
    real = socket.socket.getsockopt

    def getsockopt(sock, level, option, *size):
        if level == socket.IPPROTO_TCP and option == getattr(socket, "TCP_INFO", None):
            if refuse:
                raise OSError(errno.ENOPROTOOPT, "Protocol not available")
            return tcp_info(rtt_us)
        return real(sock, level, option, *size)
    monkeypatch.setattr(socket.socket, "getsockopt", getsockopt)


@pytest.mark.skipif(not hasattr(socket, "TCP_INFO"), reason="no TCP_INFO to stand in for on this platform")
def test_the_round_trip_is_the_kernels_and_the_slow_tag_goes_on_above_the_threshold(boxes, monkeypatch):
    box = boxes(BANNER)
    target = [Target("R7", "127.0.0.1", "ssh", box.port)]
    for rtt_us, slow_ms, tag in ((10000, 10, None),                      # at the threshold: not above it
                                 (10700, 10, "slow: answered in 10.7 ms (above 10 ms)"),
                                 (10700, 25, None),                      # --slow 25: where 10 ms is normal
                                 (270, 0.25, "slow: answered in 0.27 ms (above 0.25 ms)")):
        kernel_says(monkeypatch, rtt_us)
        r, = asyncio.run(probe.probe(target, 2, slow_ms))
        assert r.ok and r.connect_ms == rtt_us / 1000 and r.slow == tag, (rtt_us, slow_ms)
    kernel_says(monkeypatch, 0)                                          # no sample yet: the wall clock instead
    r, = asyncio.run(probe.probe(target, 2))
    assert r.ok and r.connect_ms is not None and r.connect_ms != 0


def test_where_tcp_info_is_missing_the_round_trip_is_the_connects_wall_time(boxes, monkeypatch):
    """The wall clock counts this program's own waiting too (here, 80 ms
    before the connect); the kernel's handshake round trip does not."""
    box = boxes(BANNER)
    target = [Target("R1", "127.0.0.1", "ssh", box.port)]
    real_connect = probe._connect

    async def queued(loop, sock, address):
        await asyncio.sleep(0.08)
        await real_connect(loop, sock, address)
    monkeypatch.setattr(probe, "_connect", queued)
    if hasattr(socket, "TCP_INFO"):
        r, = asyncio.run(probe.probe(target, 2))
        assert r.ok and r.connect_ms < 50                                # the kernel's: the handshake alone
        kernel_says(monkeypatch, refuse=True)
        r, = asyncio.run(probe.probe(target, 2))
        assert r.ok and r.connect_ms >= 79                               # the option refused: the wall time
        monkeypatch.delattr(socket, "TCP_INFO")
    r, = asyncio.run(probe.probe(target, 2))
    assert r.ok and r.connect_ms >= 79 and r.banner_ms is not None
    assert probe.kernel_rtt_ms(socket.socket()) is None


def test_a_slow_tag_is_information_and_never_changes_the_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(probe, "attempt", answering(slow={"10.0.0.2"}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *R12])
    assert rc == 0, err
    assert "R2  live  connect 10.7 ms  banner 16.5 ms  SSH-2.0-OpenSSH_9.6  slow: answered in 10.7 ms (above 10 ms)" \
        in out
    assert "Probe: 2 box(es) in " in out and "s: 2 live, 1 slow (above 10 ms)" in out
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", *R12])
    assert rc == 0, err
    assert ": 2 live, 1 slow (above 10 ms: R2 10.7 ms)" in out and len(driver.calls) == 2


# --- on by default, before every run --------------------------------------------------

def _files(tmp_path):
    (tmp_path / "cmds.txt").write_text("show version\nshow route summary\n")
    (tmp_path / "job.json").write_text(json.dumps([
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show route summary"}]))      # R1 twice: one box, one probe
    (tmp_path / "sets").mkdir()
    for name in ("R1", "R2"):
        (tmp_path / "sets" / f"{name}.set").write_text("set system host-name x\n")
    (tmp_path / "all.set").write_text("set system host-name x\n")


MODES = {
    "-sC": ["-sC", "show version"],
    "--batch": ["--batch", "{tmp}/cmds.txt"],
    "--profile": ["--profile", "junos-health"],
    "--job": ["--job", "{tmp}/job.json"],
    "--commit-status": ["--commit-status"],
    "--rollback": ["--rollback", "1", "-y"],
    "-eC": ["-eC", "set system host-name x", "-y"],
    "-eD": ["-eD", "{tmp}/sets", "-y"],
    "-eB": ["-eB", "{tmp}/all.set", "-y"],
    "--dry-run": ["-eC", "set system host-name x", "--dry-run"],
    "--show-diff": ["-eC", "set system host-name x", "--show-diff", "-y"],
}


@pytest.mark.parametrize("mode", list(MODES))
def test_every_mode_is_probed_first_once_per_box(monkeypatch, capsys, tmp_path, mode, probed):
    _files(tmp_path)
    argv = [a.replace("{tmp}", str(tmp_path)) for a in MODES[mode]]
    rc, out, err, _, driver = run(monkeypatch, capsys, argv + ([] if mode == "--job" else R12))
    assert rc == 0, err
    assert sorted(probed) == [("10.0.0.1", 830), ("10.0.0.2", 830)]
    assert {host for _, host in driver.calls} == {"10.0.0.1", "10.0.0.2"}
    assert "Probe: 2 box(es) in " in out and "s: 2 live" in out


def test_every_tick_of_a_watch_is_probed(monkeypatch, capsys, tmp_path):
    """A box that went away since the tick before is that tick's FAIL, in
    the probe's words, within seconds."""
    seen, ticks = [], []

    async def attempt(host, port, banner, seconds):
        seen.append((host, port))
        if host == "10.0.0.2" and len(ticks) == 2:
            return probe.Answer(probe.REFUSED, f"connection refused by {host}:{port}")
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-OpenSSH_9.6")
    monkeypatch.setattr(probe, "attempt", attempt)
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0)
    driver = Junos()
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(cli, "_watch_sleep", lambda seconds: ticks.append(seconds))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--every", "5", "--times", "3",
                                      "-sC", "show version", *R12])
    with pytest.raises(SystemExit) as e:
        cli.main_sync()
    out, err = capsys.readouterr()
    assert e.value.code == 1, err                                        # tick 3 failed a device: the worst tick's
    assert sorted(set(seen)) == [("10.0.0.1", 830), ("10.0.0.2", 830)]
    assert seen.count(("10.0.0.1", 830)) == 3 and seen.count(("10.0.0.2", 830)) == 4      # tick 3 asked twice
    assert driver.calls.count(("show", "10.0.0.2")) == 2 and driver.calls.count(("show", "10.0.0.1")) == 3
    assert "--- R2: show version: OK -> FAIL (probe: refused (connection refused by 10.0.0.2:830))" in out


def stopped_during_the_probe(monkeypatch, capsys, argv, how="cancel"):
    """main() with a Ctrl-C while the probe waits on boxes that do not
    answer: the main task cancelled, as asyncio.run does on SIGINT from
    Python 3.11 (`how` = "cancel"), or a KeyboardInterrupt raised in the
    probe, as 3.10 raises it in the code that runs ("raise"). Returns (rc,
    stdout, stderr, the driver); a KeyboardInterrupt that asyncio.run
    raises again once main() has returned is rc 130."""
    async def does_not_answer(host, port, banner, seconds):
        if how == "raise":
            raise KeyboardInterrupt
        await asyncio.sleep(30)
    monkeypatch.setattr(probe, "attempt", does_not_answer)
    driver = Junos()
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(cli, "_tty", lambda stream: False)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *argv])

    async def go():
        if how == "cancel":
            asyncio.get_running_loop().call_later(0.2, asyncio.current_task().cancel)
        return await cli.main()
    try:
        rc = asyncio.run(go())
    except KeyboardInterrupt:
        rc = 130
    out, err = capsys.readouterr()
    return rc, out, err, driver


# The reads, and the mode the store keeps each under.
READS = {"-sC": "show", "--batch": "show-batch", "--profile": "show-batch", "--job": "job",
         "--commit-status": "commit-status"}


@pytest.mark.parametrize("mode,how", [*((mode, "cancel") for mode in READS), ("-sC", "raise")])
def test_a_read_stopped_during_its_probe_is_kept_as_an_interrupted_run(monkeypatch, capsys, tmp_path, mode, how):
    """Ctrl-C while the probe waits on boxes that do not answer: no device
    was started, and the run is kept all the same, as one stopped during
    the run is: its row in the store, closed as interrupted with every
    device skipped, `Interrupted. Completed 0 of N device(s).`, the summary,
    exit 130. The row was opened after the probe, so the run left none."""
    _files(tmp_path)
    argv = [a.replace("{tmp}", str(tmp_path)) for a in MODES[mode]] + ([] if mode == "--job" else R12)
    units = 3 if mode == "--job" else 2
    rc, out, err, driver = stopped_during_the_probe(monkeypatch, capsys, argv, how)
    assert rc == 130 and driver.calls == []
    assert f"Interrupted. Completed 0 of {units} device(s)." in err
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert (summary["targets"], summary["ok"], summary["fail"], summary["skipped"], summary["interrupted"]) == (
        0, 0, 0, units, 0)
    run_row, = rows("SELECT * FROM runs")
    assert run_row["finished"] is not None and (run_row["mode"], run_row["targets"]) == (READS[mode], units)
    assert (run_row["ok"], run_row["failed"], run_row["skipped"], run_row["interrupted"]) == (0, 0, units, 1)
    assert rows("SELECT * FROM results") == []


@pytest.mark.parametrize("mode", ["-eC", "--dry-run", "--rollback"])
def test_an_edit_stopped_during_its_probe_leaves_no_run(monkeypatch, capsys, tmp_path, mode):
    """An edit's row is opened once the edit is past its questions: one
    stopped during its probe committed nothing and is no run, as one
    stopped at its question is. Ctrl-C ends it as before (exit 130)."""
    with pytest.raises(asyncio.CancelledError):
        stopped_during_the_probe(monkeypatch, capsys, MODES[mode] + R12)
    assert rows("SELECT * FROM runs") == []


def test_a_dead_box_is_a_fail_of_the_run_in_the_probes_words_and_is_not_touched(monkeypatch, capsys):
    """A read goes to the live boxes; the dead one fails within seconds with
    the probe's reason (exit 1, a device failed), in --json and in the
    store like any failed device, instead of a worker spent on its
    connect timeouts."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", *R12])
    assert rc == 1 and driver.calls == [("show", "10.0.0.1")]
    assert ": 1 live, 1 dead (refused 1)" in out
    assert "R2               FAIL\n  ERROR: probe: refused (connection refused by 10.0.0.2:830)" in out
    assert '"ok": 1, "fail": 1' in err
    failed, = rows("SELECT * FROM results WHERE ok = 0")
    assert failed["device"] == "R2" and failed["error"] == "probe: refused (connection refused by 10.0.0.2:830)"
    assert failed["command"] == "show version"
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", "--json", *R12])
    assert rc == 1 and driver.calls == [("show", "10.0.0.1")]
    by_name = {e["device"]: e for e in json.loads(out)}
    assert by_name["R2"]["ok"] is False and by_name["R2"]["error"] == "probe: refused (connection refused by 10.0.0.2:830)"
    assert by_name["R1"]["ok"] is True


def test_a_name_no_resolver_takes_fails_its_own_device_and_the_rest_run(boxes, monkeypatch, capsys):
    """A typo'd `10.0.0..1` in the inventory is that device's FAIL, as it was
    before the probe and is with --no-probe: --probe alone lists it as name
    not found and finishes its run, a read runs the others, an edit stops
    on it as on any dead box. No traceback, nothing else held up."""
    live = boxes(BANNER)
    targets = ["R1:10.0.0..1:junos", f"R2:127.0.0.1:{live.port}:junos"]
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *targets])
    assert rc == 1, err
    assert "R2  live            connect " in out
    line, = [ln for ln in out.splitlines() if ln.startswith("R1 ")]
    assert line.startswith("R1  name not found  cannot resolve 10.0.0..1: label empty")
    run_row, = rows("SELECT * FROM runs")
    assert run_row["finished"] is not None and (run_row["ok"], run_row["failed"], run_row["interrupted"]) == (1, 1, 0)
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", *targets])
    assert rc == 1 and driver.calls == [("show", "127.0.0.1")]
    assert "R1               FAIL\n  ERROR: probe: name not found (cannot resolve 10.0.0..1: " in out
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "-y", *targets])
    assert rc == 2 and driver.calls == [] and "ERROR: 1 device(s) unreachable: R1" in out


def test_the_summary_says_how_long_the_probe_took(monkeypatch, capsys):
    """elapsed_ms is the run's own, from the confirmation on, as before the
    probe; probe_ms is the probe before it, so a run whose time went into
    the probe does not read as one that took none. Without the probe there
    is no probe_ms."""
    async def slow_to_answer(host, port, banner, seconds):
        await asyncio.sleep(0.5)
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-OpenSSH_9.6")
    monkeypatch.setattr(probe, "attempt", slow_to_answer)
    rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", *R12])
    summary = json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])
    assert rc == 0 and summary["probe_ms"] >= 490 and "elapsed_ms" in summary
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--no-probe", "-sC", "show version", *R12])
    assert rc == 0 and "probe_ms" not in json.loads(err.split("[h-ssh] ", 1)[1].splitlines()[0])


def test_no_probe_and_probe_no_in_the_config_skip_it_and_probe_turns_it_back_on(monkeypatch, capsys, tmp_path,
                                                                                probed):
    rc, out, err, _, driver = run(monkeypatch, capsys, ["--no-probe", "-sC", "show version", *R12])
    assert rc == 0 and probed == [] and len(driver.calls) == 2 and "Probe:" not in out
    cfg = tmp_path / "config"
    for word in ("no", "No", "off", "false", "0"):
        cfg.write_text(f"probe = {word}\n")
        rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", *R12], config=str(cfg))
        assert rc == 0 and probed == [], word
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "-sC", "show version", *R12], config=str(cfg))
    assert rc == 0 and sorted(probed) == [("10.0.0.1", 830), ("10.0.0.2", 830)]   # the flag wins over the file
    del probed[:]
    run_file = tmp_path / "run.json"
    run_file.write_text(json.dumps({"no_probe": True, "show": "show version", "devices": R12}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--run", str(run_file)])
    assert rc == 0 and probed == []
    cfg.write_text("probe = maybe\n")
    rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", *R12], config=str(cfg))
    assert rc == 2 and "probe = 'maybe' is not yes or no" in err
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--no-probe", "-sC", "show version", *R12])
    assert rc == 2 and "ERROR: --probe and --no-probe contradict each other." in err
    assert probed == []


def test_probe_typed_on_the_command_line_wins_over_a_run_files_no_probe(monkeypatch, capsys, tmp_path, probed):
    """A flag typed on the command line wins over the run file, --probe
    over its no_probe as over any key; only both flags typed contradict
    each other."""
    run_file = tmp_path / "run.json"
    run_file.write_text(json.dumps({"no_probe": True, "show": "show version", "devices": R12}))
    rc, out, err, _, driver = run(monkeypatch, capsys, ["--run", str(run_file), "--probe"])
    assert rc == 0, err
    assert sorted(probed) == [("10.0.0.1", 830), ("10.0.0.2", 830)] and len(driver.calls) == 2
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--run", str(run_file), "--probe", "--no-probe"])
    assert rc == 2 and "ERROR: --probe and --no-probe contradict each other." in err


def test_a_box_the_safety_gate_holds_is_not_probed_either(monkeypatch, capsys, tmp_path, probed):
    """The safety gate keeps a box that failed away for its cooldown, to
    spare the router's ssh rate-limit. The probe is a connection too: it
    passes the box over (not probed, the gate's reason), on every run and
    tick as on --probe alone, and the run's gate turns it away as before
    (exit 3: nothing failed, not everything ran)."""
    from hssh.safety import SafetyGate
    safety = tmp_path / "safety.json"
    gate = SafetyGate(safety_file=str(safety))
    gate.set_cooldown("10.0.0.2")
    gate.close()
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", "--safety-file", str(safety), *R12])
    assert rc == 3, err
    assert probed == [("10.0.0.1", 830)] and driver.calls == [("show", "10.0.0.1")]
    assert ": 1 live, 1 not probed" in out and "ERROR: safety gate blocked: cooldown active (" in out
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--safety-file", str(safety), *R12])
    assert rc == 3 and probed == [("10.0.0.1", 830)] * 2
    assert "R2  not probed  safety gate: cooldown active (" in out
    assert '"ok": 1, "fail": 0, "skipped": 1' in err


def test_the_safety_gate_holds_a_device_not_its_whole_address(monkeypatch, capsys, tmp_path, probed):
    """A cooldown is the device's own, its host and its port (#145): one on
    R1's NETCONF port does not keep the probe or the run from R2 on the ssh
    port of the same address, where the gate held the address whole. One
    an older h-ssh kept under the address alone still holds both."""
    from hssh.safety import SafetyGate
    safety = tmp_path / "safety.json"
    gate = SafetyGate(safety_file=str(safety))
    gate.set_cooldown("10.0.0.1", 830)
    gate.close()
    driver = Junos()
    monkeypatch.setitem(drivers.MODULES, "junos@ssh", driver)
    both = ["R1:10.0.0.1:junos", "R2:10.0.0.1:junos@ssh"]
    rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", "--safety-file", str(safety), *both],
                             driver=driver)
    assert rc == 3, err
    assert probed == [("10.0.0.1", 22)] and driver.calls == [("show", "10.0.0.1")]
    assert ": 1 live, 1 not probed" in out and "ERROR: safety gate blocked: cooldown active (" in out
    safety.write_text(json.dumps({"10.0.0.1": time.time() + 300}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", "--safety-file", str(safety), *both],
                             driver=driver)
    assert rc == 3 and probed == [("10.0.0.1", 22)] and len(driver.calls) == 1, err


# --- before an edit: the probe's question ---------------------------------------------

@pytest.mark.parametrize("answer", ["y", "N"])
def test_an_edit_at_a_terminal_names_the_dead_and_asks_before_going_on_without_them(monkeypatch, capsys, tmp_path,
                                                                                   answer):
    """-y confirms the edit; it does not accept a partial deployment, so the
    question is asked with -y too. Yes: the reachable get the change, the
    dead one is skipped (exit 3: not everything ran). No: nothing is sent
    (exit 2, as the pre-flight's abort)."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    audit = tmp_path / "audit.jsonl"
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "-y", "--audit-log",
                                                            str(audit), *R12], tty=True, answer=answer)
    assert asked == ["Continue with the 1 reachable? [y/N]: "]
    assert "  R2               (10.0.0.2) refused (connection refused by 10.0.0.2:830)" in out
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    if answer == "y":
        assert rc == 3 and driver.calls == [("edit", "10.0.0.1")]
        assert "R2               SKIPPED\n  ERROR: probe: refused (connection refused by 10.0.0.2:830); skipped" in out
        assert "Done. OK: 1, skipped as unreachable: 1" in out
        assert '"ok": 1, "fail": 0, "skipped": 1' in err
        run_row, = rows("SELECT * FROM runs")
        assert (run_row["ok"], run_row["failed"], run_row["skipped"]) == (1, 0, 1)
        assert {(r["device"], r["ok"]) for r in records} == {("R1", True), ("R2", False)}
    else:
        assert rc == 2 and driver.calls == []
        assert "ERROR: 1 device(s) unreachable: R2" in out and "Aborting to prevent partial deployment" in out
        assert [(r["device"], r["error"]) for r in records] == [
            ("R2", "preflight probe failed: refused (connection refused by 10.0.0.2:830) (aborted)")]


def test_with_json_the_dead_and_the_question_go_to_the_terminal_and_stdout_stays_json(monkeypatch, capsys):
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "-y", "--json", *R12],
                                      tty=True, answer="yes")
    assert rc == 3 and asked == ["Continue with the 1 reachable? [y/N]: "] and driver.calls == [("edit", "10.0.0.1")]
    assert "  R2               (10.0.0.2) refused (connection refused by 10.0.0.2:830)" in err
    assert sorted(e["device"] for e in json.loads(out)) == ["R1", "R2"]


def test_without_a_terminal_a_dead_box_stops_the_edit_unless_skip_unreachable(monkeypatch, capsys, tmp_path):
    """-y is no answer to the probe's question: without a terminal the edit
    is refused (exit 2, as today); --skip-unreachable goes on with the
    reachable and the skipped make it exit 3."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "-y", *R12])
    assert rc == 2 and driver.calls == [] and asked == []
    assert "ERROR: 1 device(s) unreachable: R2" in out
    assert "Aborting to prevent partial deployment; --skip-unreachable goes on with the 1 reachable." in out
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "-y", "--json", *R12])
    assert rc == 2 and driver.calls == []
    assert json.loads(out) == {"error": "1 device(s) unreachable", "unreachable": ["R2"],
                               "reasons": {"R2": "refused (connection refused by 10.0.0.2:830)"}}
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "-y", "--json",
                                                            "--skip-unreachable", *R12])
    assert rc == 3 and driver.calls == [("edit", "10.0.0.1")] and asked == []
    assert "Skipping 1 unreachable device(s) (--skip-unreachable): R2" in err
    by_name = {e["device"]: e for e in json.loads(out)}
    assert by_name["R1"]["ok"] and by_name["R2"]["error"].endswith("; skipped")
    assert '"skipped": 1' in err
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "--skip-unreachable",
                                                            *R12])
    assert rc == 2 and "requires confirmation but stdin is not a TTY" in err and driver.calls == []
    run_file = tmp_path / "edit.json"                                   # the same, from a run file
    run_file.write_text(json.dumps({"edit": "set system host-name x", "devices": R12, "commit_confirmed": 5,
                                    "yes": True, "skip_unreachable": True}))
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["--run", str(run_file)])
    assert rc == 3 and driver.calls == [("edit", "10.0.0.1")]


@pytest.mark.parametrize("edit", ["-eC", "--show-diff", "--rollback", "--job"])
def test_an_edit_without_y_or_a_terminal_is_refused_before_the_probe_touches_a_box(monkeypatch, capsys, tmp_path,
                                                                                   probed, edit):
    """An edit nobody can confirm (no -y, no terminal) is refused before the
    probe: a pipeline that left out -y costs the routers no pre-auth
    connection, which their ssh rate-limit would count, and sends nothing."""
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                               {"target": "R2:10.0.0.2:junos", "edit": "set system host-name x"}]))
    argv = {"-eC": ["-eC", "set system host-name x", *R12],
            "--show-diff": ["-eC", "set system host-name x", "--show-diff", *R12],
            "--rollback": ["--rollback", "1", *R12],
            "--job": ["--job", str(job)]}[edit]
    rc, out, err, asked, driver = run(monkeypatch, capsys, argv)
    assert rc == 2 and asked == [] and driver.calls == []
    assert probed == [] and "Probe:" not in out
    assert ("--show-diff needs a terminal to ask, or -y." if edit == "--show-diff" else
            "Edit operation requires confirmation but stdin is not a TTY. Use -y to skip.") in err


def test_a_job_with_an_edit_goes_on_without_a_dead_box_only_when_told(monkeypatch, capsys, tmp_path):
    """A job with an edit entry is an edit: its dead box stops it without a
    terminal, and with --skip-unreachable every entry of that box is
    skipped while the others run."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                               {"target": "R2:10.0.0.2:junos", "edit": "set system host-name x"},
                               {"target": "R2:10.0.0.2:junos", "show": "show version"}]))
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["--job", str(job), "-y"])
    assert rc == 2 and driver.calls == [] and "1 device(s) unreachable: R2" in out
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["--job", str(job), "-y", "--skip-unreachable", "--json"])
    assert rc == 3 and driver.calls == [("show", "10.0.0.1")]
    entries = json.loads(out)
    assert sorted((e["device"], e["ok"]) for e in entries) == [("R1", True), ("R2", False), ("R2", False)]
    assert '"skipped": 2' in err
    assert [r["seq"] for r in rows("SELECT seq FROM results WHERE device = 'R2' ORDER BY seq")] == [0, 1]


def last_run():
    run_row, = rows("SELECT * FROM runs ORDER BY rowid DESC LIMIT 1")
    return run_row


def test_a_dead_box_a_job_only_reads_is_a_fail_and_does_not_stop_its_edit(monkeypatch, capsys, tmp_path):
    """The probe's question, its abort and --skip-unreachable are about the
    boxes the edit goes to. A job whose dead box only has shows goes on with
    nothing asked: those shows are a FAIL of the run (exit 1), as in a show
    run, where the edit used to be stopped (exit 2) or, with
    --skip-unreachable, the shows SKIPPED (exit 3)."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.3"}))
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                               {"target": "R2:10.0.0.2:junos", "edit": "set system host-name x"},
                               {"target": "R3:10.0.0.3:junos", "show": "show version"}]))
    for extra, tty in (([], False), (["--skip-unreachable"], False), ([], True), (["--dry-run"], False)):
        rc, out, err, asked, driver = run(monkeypatch, capsys, ["--job", str(job), "-y", *extra], tty=tty)
        assert rc == 1 and asked == [], (extra, tty, out, err)
        sent = [("dry-run", "10.0.0.2")] if "--dry-run" in extra else [("edit", "10.0.0.2"), ("show", "10.0.0.1")]
        assert sorted(driver.calls) == sent                                 # a dry run's show is not sent
        assert "R3               FAIL\n  ERROR: probe: refused (connection refused by 10.0.0.3:830)\n" in out
        assert "Aborting" not in out and "SKIPPED" not in out and "Skipping" not in err
        assert ("Ready to execute" not in out) if "--dry-run" in extra else ("Ready to execute on 2 device(s)." in out)
        assert '"ok": 2, "fail": 1, "skipped": 0' in err
        assert (last_run()["ok"], last_run()["failed"], last_run()["skipped"]) == (2, 1, 0)


def test_a_job_asks_about_the_dead_boxes_it_edits_and_fails_the_ones_it_only_reads(monkeypatch, capsys, tmp_path):
    """With a dead box the edit goes to and another the job only reads, the
    question and the abort name the first alone; going on without it skips
    its entries, and the other's show is a FAIL (exit 1: a device failed)."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2", "10.0.0.3"}))
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                               {"target": "R2:10.0.0.2:junos", "edit": "set system host-name x"},
                               {"target": "R2:10.0.0.2:junos", "show": "show version"},
                               {"target": "R3:10.0.0.3:junos", "show": "show version"}]))
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["--job", str(job), "-y"])
    assert rc == 2 and driver.calls == []
    assert "ERROR: 1 device(s) unreachable: R2\n" in out and "R3               (10.0.0.3)" not in out
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["--job", str(job), "-y"], tty=True, answer="y")
    assert rc == 1 and asked == ["Continue with the 1 reachable? [y/N]: "] and driver.calls == [("show", "10.0.0.1")]
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["--job", str(job), "-y", "--skip-unreachable"])
    assert rc == 1 and driver.calls == [("show", "10.0.0.1")]
    assert "Skipping 1 unreachable device(s) (--skip-unreachable): R2" in err
    assert out.count("R2               SKIPPED") == 2 and "R3               FAIL" in out
    assert "Done. Failures: 1, skipped as unreachable: 2" in out
    assert (last_run()["ok"], last_run()["failed"], last_run()["skipped"]) == (1, 1, 2)


def test_an_edit_with_every_box_dead_is_refused_and_asks_nothing(monkeypatch, capsys):
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.1", "10.0.0.2"}))
    for argv, tty in ((["-y"], True), (["-y", "--skip-unreachable"], False)):
        rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", *argv, *R12],
                                          tty=tty)
        assert rc == 2 and driver.calls == [] and asked == []
        assert "ERROR: 2 device(s) unreachable: R1, R2" in out
        assert "Aborting to prevent partial deployment: no device answered the probe." in out


def test_a_dry_run_is_asked_and_stopped_as_the_edit_it_rehearses(monkeypatch, capsys):
    """A dry run rehearses the edit, the probe's question included: at a
    terminal it asks before it goes on without a dead box (y: the box is
    skipped, exit 3; N: nothing is sent, exit 2), without one it stops
    (exit 2) unless --skip-unreachable. It still needs neither -y nor a
    terminal to start."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    dry = ["-eC", "set system host-name x", "--dry-run", *R12]
    rc, out, err, asked, driver = run(monkeypatch, capsys, dry, tty=True, answer="y")
    assert rc == 3 and asked == ["Continue with the 1 reachable? [y/N]: "] and driver.calls == [("dry-run", "10.0.0.1")]
    assert "R2               SKIPPED\n  ERROR: probe: refused (connection refused by 10.0.0.2:830); skipped" in out
    rc, out, err, asked, driver = run(monkeypatch, capsys, dry, tty=True, answer="N")
    assert rc == 2 and driver.calls == [] and "ERROR: 1 device(s) unreachable: R2" in out
    rc, out, err, asked, driver = run(monkeypatch, capsys, dry)
    assert rc == 2 and asked == [] and driver.calls == []
    assert "Aborting to prevent partial deployment; --skip-unreachable goes on with the 1 reachable." in out
    rc, out, err, asked, driver = run(monkeypatch, capsys, [*dry, "--skip-unreachable"])
    assert rc == 3 and asked == [] and driver.calls == [("dry-run", "10.0.0.1")]


def test_show_diff_previews_only_the_boxes_that_answered(monkeypatch, capsys):
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    rc, out, err, asked, driver = run(monkeypatch, capsys, ["-eC", "set system host-name x", "--show-diff", "-y",
                                                            "--skip-unreachable", *R12])
    assert rc == 3 and driver.calls == [("dry-run", "10.0.0.1"), ("edit", "10.0.0.1")]
    assert "--- R1: diff ---" in out and "--- R2" not in out


# --- --probe alone: the health check --------------------------------------------------

def test_probe_alone_prints_a_line_per_box_and_a_summary_and_logs_in_nowhere(monkeypatch, capsys):
    """No password is read or asked for, at a terminal either, and no
    transport is needed: here the junos one is not even installed."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}, slow={"10.0.0.3"}, silent={"10.0.0.4"}))
    targets = [*R12, "R3:10.0.0.3:junos", "R4:10.0.0.4:junos", "SW1:10.0.0.5:telnet-ios"]
    rc, out, err, asked, _ = run(monkeypatch, capsys, ["--probe", *targets], tty=True, password=None,
                                 driver=types.SimpleNamespace(AVAILABLE=False))
    assert rc == 1 and asked == []
    lines = out.splitlines()
    assert "Probe: 5 box(es), 5 at a time, 3s for the TCP connect and 3s for the banner" in lines
    assert lines[lines.index("Probe: 5 box(es), 5 at a time, 3s for the TCP connect and 3s for the banner") + 1:][:5] == [
        "R1   live     connect 0.4 ms  banner 7.2 ms  SSH-2.0-OpenSSH_9.6",
        "R2   refused  connection refused by 10.0.0.2:830",
        "R3   live     connect 10.7 ms  banner 16.5 ms  SSH-2.0-OpenSSH_9.6  slow: answered in 10.7 ms (above 10 ms)",
        "R4   silent   connect 0.4 ms  no SSH banner from 10.0.0.4:830 within 3s",
        "SW1  live     connect 0.4 ms  TCP only, no banner to check",
    ]
    assert lines[-1].startswith("Probe: 5 box(es) in ")
    assert lines[-1].endswith("s: 3 live, 2 dead (refused 1, silent 1), 1 slow (above 10 ms)")
    summary = json.loads(err.split("[h-ssh] ", 1)[1])
    assert {k: summary[k] for k in ("targets", "ok", "fail", "skipped", "slow", "mode")} == {
        "targets": 5, "ok": 3, "fail": 2, "skipped": 0, "slow": 1, "mode": "probe"}


def test_probe_alone_in_a_pipeline_with_hssh_password_set_but_empty_still_probes(monkeypatch, capsys):
    """#136 review: an HSSH_PASSWORD set but empty refuses a pipeline run,
    which would go on to keys without a word; that refusal now comes before
    anything is written, and a probe, which logs in nowhere, is no such run:
    it probes and is kept, no error."""
    rc, out, err, asked, _ = run(monkeypatch, capsys, ["--probe", *R12], tty=False, password="")
    assert rc == 0 and asked == [] and "set but empty" not in err, err
    assert [r["device"] for r in rows("SELECT device FROM results ORDER BY device")] == ["R1", "R2"]


def test_probe_alone_is_a_run_in_the_store_with_a_row_per_box(monkeypatch, capsys):
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *R12])
    assert rc == 1
    run_row, = rows("SELECT * FROM runs")
    assert (run_row["mode"], run_row["command"], run_row["targets"], run_row["ok"], run_row["failed"]) == (
        "probe", "probe", 2, 1, 1)
    assert run_row["finished"] is not None and "--probe" in run_row["argv"]
    kept = {r["device"]: r for r in rows("SELECT * FROM results")}
    assert set(kept) == {"R1", "R2"} and all(r["command"] == "probe" and r["format"] == "json" for r in kept.values())
    assert kept["R1"]["ok"] == 1 and kept["R1"]["error"] is None
    assert kept["R2"]["ok"] == 0 and kept["R2"]["error"] == "refused (connection refused by 10.0.0.2:830)"
    record = json.loads(kept["R1"]["output"])
    assert (record["result"], record["connect_ms"], record["banner_ms"], record["banner"], record["port"]) == (
        "live", 0.4, 7.2, "SSH-2.0-OpenSSH_9.6", 830)
    assert store_main(["failed"]) == 1
    printed = capsys.readouterr().out
    assert "1 failed" in printed and "R2" in printed and "refused (connection refused by 10.0.0.2:830)" in printed
    assert store_main(["field", "connect_ms"]) == 0 and "R1  connect_ms = 0.4" in capsys.readouterr().out


def test_probe_alone_writes_the_audit_log_and_the_run_log(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))
    audit, log = tmp_path / "audit.jsonl", tmp_path / "run.jsonl"
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--audit-log", str(audit), "--log", str(log), *R12])
    assert rc == 1
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [(e["device"], e["mode"], e["ok"], e.get("error")) for e in entries] == [
        ("R1", "probe", True, None), ("R2", "probe", False, "refused (connection refused by 10.0.0.2:830)")]
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(r["device"], r["mode"], r["result"], r["connect_ms"]) for r in lines] == [
        ("R1", "probe", "live", 0.4), ("R2", "probe", "refused", None)]


def test_probe_alone_that_the_store_could_not_keep_exits_4(monkeypatch, capsys):
    from hssh.store import Store

    def full(self, *a, **kw):
        raise OSError("database or disk is full")
    monkeypatch.setattr(Store, "add_entry", full)
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *R12])
    assert rc == 4 and "2 of 2 results were not kept: database or disk is full" in err
    assert '"not_kept": 2' in err


def test_probe_alone_stopped_by_ctrl_c_leaves_its_run_recorded_as_interrupted(monkeypatch, capsys):
    async def slow_to_answer(host, port, banner, seconds):
        await asyncio.sleep(5)
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-x")
    monkeypatch.setattr(probe, "attempt", slow_to_answer)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--probe", *R12])

    async def go():
        asyncio.get_running_loop().call_later(0.2, asyncio.current_task().cancel)   # as asyncio.run does on SIGINT
        return await cli.main()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(go())
    run_row, = rows("SELECT * FROM runs")
    assert (run_row["mode"], run_row["ok"], run_row["failed"], run_row["skipped"], run_row["interrupted"]) == (
        "probe", 0, 0, 2, 1)
    assert rows("SELECT * FROM results") == []


def test_probe_alone_that_ends_on_something_unexpected_still_finishes_its_run_row(monkeypatch, capsys):
    """Not only Ctrl-C: whatever ends --probe alone before its results, its
    run row is finished as interrupted, every box skipped, never left
    open."""
    async def broken(*a, **kw):
        raise RuntimeError("a bug")
    monkeypatch.setattr(probe, "probe", broken)
    with pytest.raises(RuntimeError, match="a bug"):
        run(monkeypatch, capsys, ["--probe", *R12])
    run_row, = rows("SELECT * FROM runs")
    assert run_row["finished"] is not None
    assert (run_row["ok"], run_row["failed"], run_row["skipped"], run_row["interrupted"]) == (0, 0, 2, 1)


@pytest.mark.parametrize("cut", [BrokenPipeError, KeyboardInterrupt])
def test_probe_alone_keeps_its_record_when_its_report_is_cut_short(monkeypatch, capsys, cut):
    """The record is written before the report is printed: a reader that
    leaves early (`| head`, BrokenPipeError) or a Ctrl-C while the report
    prints (where Python 3.10 raises KeyboardInterrupt) costs the report,
    never the rows, and the run row is closed as interrupted with what the
    probe found."""
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}))

    class Reader:
        """stdout whose reader goes away after the header."""
        lines = 0

        def write(self, text):
            self.lines += text.count("\n")
            if self.lines > 2:
                raise cut()
            return len(text)

        def flush(self):
            pass
    monkeypatch.setattr(sys, "stdout", Reader())
    with pytest.raises(cut):
        run(monkeypatch, capsys, ["--probe", *R12])
    run_row, = rows("SELECT * FROM runs")
    assert run_row["finished"] is not None
    assert (run_row["ok"], run_row["failed"], run_row["skipped"], run_row["interrupted"]) == (1, 1, 0, 1)
    assert [(r["device"], r["ok"], r["error"]) for r in rows("SELECT * FROM results ORDER BY device")] == [
        ("R1", 1, None), ("R2", 0, "refused (connection refused by 10.0.0.2:830)")]


def test_probe_alone_with_json_gives_the_records_and_exit_0_when_every_box_is_live(monkeypatch, capsys):
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--json", *R12])
    assert rc == 0, err
    records = json.loads(out)
    assert [r["device"] for r in records] == ["R1", "R2"]
    assert records[0] == {"device": "R1", "host": "10.0.0.1", "port": 830, "vendor": "junos", "ok": True,
                          "result": "live", "connect_ms": 0.3, "banner_ms": 7.0, "banner": "SSH-2.0-OpenSSH_9.6",
                          "reason": None, "slow": None, "duration_ms": records[0]["duration_ms"]}
    assert "Probe:" not in out


def test_probe_alone_against_real_boxes(boxes, monkeypatch, capsys):
    live = boxes(BANNER)
    dead = refused_port()
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--connect-timeout", "2", f"R1:127.0.0.1:{live.port}:ssh",
                                                   f"R2:127.0.0.1:{dead}:ssh"])
    assert rc == 1
    assert "R1  live     connect " in out and "SSH-2.0-OpenSSH_9.6" in out
    assert f"R2  refused  connection refused by 127.0.0.1:{dead}" in out


def test_probe_goes_alone_or_with_a_command_and_not_with_a_watch(monkeypatch, capsys):
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--every", "5", *R12])
    assert rc == 2 and "not edits, rollbacks, commit status, jobs or --probe" in err
    rc, out, err, _, _ = run(monkeypatch, capsys, R12)
    assert rc == 2 and "(or --probe alone, to check the boxes)" in err


def test_slow_is_a_flag_a_config_key_and_a_run_file_key(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(probe, "attempt", answering(slow={"10.0.0.2"}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--slow", "25", *R12])
    assert rc == 0 and "slow:" not in out and "s: 2 live" in out
    cfg = tmp_path / "config"
    cfg.write_text("slow = 5\n")
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *R12], config=str(cfg))
    assert rc == 0 and "slow: answered in 10.7 ms (above 5 ms)" in out
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--slow", "12.5", *R12], config=str(cfg))
    assert rc == 0 and "slow:" not in out                                 # the flag wins over the file
    run_file = tmp_path / "run.yaml"
    run_file.write_text(json.dumps({"slow": 2.5, "devices": R12}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--run", str(run_file), "--probe"])
    assert rc == 0 and "slow: answered in 10.7 ms (above 2.5 ms)" in out
    for value, needle in (("0", "--slow takes milliseconds above 0, up to 86400000, not 0"),
                          ("nan", "--slow takes milliseconds above 0, up to 86400000, not nan"),
                          ("fast", "--slow takes milliseconds, not 'fast'")):
        with pytest.raises(SystemExit) as e:
            run(monkeypatch, capsys, ["--probe", "--slow", value, *R12])
        assert e.value.code == 2 and needle in capsys.readouterr().err
    for text, needle in (("slow = 0\n", "slow = 0 is not above 0"), ("slow = soon\n", "slow = 'soon' is not a number")):
        cfg.write_text(text)
        rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *R12], config=str(cfg))
        assert rc == 2 and needle in err
    run_file.write_text(json.dumps({"slow": 0, "devices": R12}))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--run", str(run_file), "--probe"])
    assert rc == 2 and "'slow' must be above 0 milliseconds, not 0" in err


def test_the_help_names_the_probes_flags(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--help"])
    with pytest.raises(SystemExit) as e:
        asyncio.run(cli.main())
    out = re.sub(r"(?<=\w-) (?=\w)", "", " ".join(capsys.readouterr().out.split()))     # argparse wraps at hyphens
    assert e.value.code == 0
    for needle in ("--probe Alone, with no command: check every box without logging in",
                   "--no-probe Skip the probe that runs before every run",
                   "--slow MS The probe tags a live box whose TCP handshake took longer than MS milliseconds",
                   "--skip-unreachable Edits: go on with the boxes that answered the probe, without asking",
                   "-y, --yes Skip confirmation prompt for edit operations (not the probe's question about "
                   "unreachable boxes; see --skip-unreachable)"):
        assert needle in out, needle


# --- where the run goes: the ssh client's configuration --------------------------------

no_ssh = pytest.mark.skipif(shutil.which("ssh") is None, reason="no OpenSSH client here")


@no_ssh
def test_an_openssh_box_is_probed_where_its_ssh_config_sends_it_and_not_past_a_proxy(boxes, monkeypatch, capsys,
                                                                                     tmp_path):
    """The openssh transport goes where the OpenSSH client's configuration
    says: a HostName and a Port there move the box, a ProxyJump or a
    ProxyCommand puts it behind a host the probe cannot see past. The probe
    asks `ssh -G` (here reading the test's file through -F) and goes where
    the run goes; a box behind a proxy is not probed and the run goes to
    it, so a ProxyJump stanza still works with no extra flags."""
    live = boxes(BANNER)
    cfg = tmp_path / "ssh_config"
    cfg.write_text(f"Host r1.invalid\n  HostName 127.0.0.1\n  Port {live.port}\n"
                   "Host r2.invalid\n  ProxyJump bastion.invalid\n"
                   "Host r3.invalid\n  ProxyCommand ssh -W %h:%p bastion.invalid\n")
    monkeypatch.setattr(probe, "SSH_G", ("ssh", "-F", str(cfg), "-G"))
    targets = ["R1:r1.invalid:openssh", "R2:r2.invalid:openssh", "R3:r3.invalid:openssh"]
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *targets])
    assert rc == 3, err                                         # nothing dead, not everything probed
    assert "R1  live        connect " in out and "SSH-2.0-OpenSSH_9.6" in out
    assert "R2  not probed  reached through ProxyJump bastion.invalid (ssh -G)" in out
    assert "R3  not probed  reached through ProxyCommand ssh -W %h:%p bastion.invalid (ssh -G)" in out
    assert "s: 1 live, 2 not probed" in out
    kept = {r["device"]: json.loads(r["output"]) for r in rows("SELECT * FROM results")}
    assert (kept["R1"]["host"], kept["R1"]["port"], kept["R2"]["result"]) == ("r1.invalid", live.port, "not probed")
    driver = Junos()
    monkeypatch.setitem(drivers.MODULES, "none@openssh", driver)
    rc, out, err, _, _ = run(monkeypatch, capsys, ["-sC", "show version", *targets], driver=driver)
    assert rc == 0, err                                         # the run, not the probe, goes through the jump
    assert sorted(driver.calls) == [("show", "r1.invalid"), ("show", "r2.invalid"), ("show", "r3.invalid")]
    assert "s: 1 live, 2 not probed" in out


def test_a_junos_box_is_probed_where_its_ssh_config_sends_it(boxes, monkeypatch, capsys, tmp_path):
    """PyEZ and ncclient read ~/.ssh/config for the junos transport: its
    HostName, its Port (over the target's own, as PyEZ takes it) and a
    ProxyCommand, which the probe cannot follow. A ProxyJump they do not
    read, and neither does the probe: that box is asked directly, as the
    run will ask it."""
    live = boxes(BANNER)
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "config").write_text(f"Host r1.invalid\n  HostName 127.0.0.1\n  Port {live.port}\n"
                                              "Host r2.invalid\n  ProxyCommand ssh -W %h:%p bastion.invalid\n"
                                              "Host r3.invalid\n  ProxyJump bastion.invalid\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(probe, "SSH_CONFIG", None)                 # ~/.ssh/config, found as PyEZ finds it
    targets = ["R1:r1.invalid:junos:830", "R2:r2.invalid:junos", "R3:r3.invalid:junos"]
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", *targets])
    assert rc == 1, err
    assert "R1  live            connect " in out
    assert "R2  not probed      reached through ProxyCommand (~/.ssh/config)" in out
    assert "R3  name not found  " in out
    kept = {r["device"]: json.loads(r["output"]) for r in rows("SELECT * FROM results")}
    assert [kept[d]["port"] for d in ("R1", "R2", "R3")] == [live.port, 830, 830]
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", *targets[:2]])
    assert rc == 0 and sorted(driver.calls) == [("show", "r1.invalid"), ("show", "r2.invalid")]
    assert "s: 1 live, 1 not probed" in out


def test_a_junos_box_on_port_23_is_a_console_and_is_asked_tcp_alone(monkeypatch, capsys, tmp_path):
    """PyEZ makes a junos Device on port 23 a Console and telnets to it, and
    a console sends no SSH banner: the probe asks it TCP alone, as it asks
    telnet, where it asked for a banner and called the console's telnet
    negotiation not SSH, a dead box (its read a FAIL, its edit stopped).
    Of ~/.ssh/config the Console reads the Port alone: it telnets to the
    host as given, through no ProxyCommand, and the probe asks it there."""
    asked = []

    async def a_console_on_23(host, port, banner, seconds):
        asked.append((host, port, banner))
        if banner is None:
            return probe.Answer(probe.LIVE, connect_ms=0.4)
        if port in (23, 2323):
            return probe.Answer(probe.NOT_SSH, f"{host}:{port} answered '\\xff\\xfd\\x18', not an SSH banner", 0.4)
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-OpenSSH_9.6")
    monkeypatch.setattr(probe, "attempt", a_console_on_23)
    rc, out, err, _, driver = run(monkeypatch, capsys, ["-sC", "show version", "CON1:10.0.0.9:junos:23", *R12])
    assert rc == 0, out
    assert sorted(asked) == [("10.0.0.1", 830, b"SSH-"), ("10.0.0.2", 830, b"SSH-"), ("10.0.0.9", 23, None)]
    assert sorted(driver.calls) == [("show", "10.0.0.1"), ("show", "10.0.0.2"), ("show", "10.0.0.9")]
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "CON1:10.0.0.9:junos:23"])
    assert rc == 0 and "CON1  live  connect 0.4 ms  TCP only, no banner to check" in out
    config = tmp_path / "config"
    config.write_text("Host 10.0.0.9\n  HostName 10.0.0.99\n  Port 2323\n  ProxyCommand ssh -W %h:%p bastion.invalid\n")
    monkeypatch.setattr(probe, "SSH_CONFIG", str(config))
    asked.clear()
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "CON1:10.0.0.9:junos:23"])
    assert rc == 0 and asked == [("10.0.0.9", 2323, None)], out


def test_a_junos_console_answers_the_probe_with_its_telnet_negotiation(boxes, monkeypatch, capsys, tmp_path):
    """A console that speaks telnet (IAC DO TERMINAL-TYPE, ...) where an SSH
    server would send its banner is live to the probe when PyEZ will reach
    it as a console, on a junos target's port 23 (here moved by the Port
    in ~/.ssh/config, as PyEZ's Console takes it, since no test listens on
    23): it used to be not SSH."""
    console = boxes(b"\xff\xfd\x18\xff\xfd \xff\xfb\x01")
    config = tmp_path / "config"
    config.write_text(f"Host 127.0.0.1\n  Port {console.port}\n")
    monkeypatch.setattr(probe, "SSH_CONFIG", str(config))
    rc, out, err, _, _ = run(monkeypatch, capsys, ["--probe", "--connect-timeout", "2", "CON1:127.0.0.1:junos:23"])
    assert rc == 0, out
    assert re.search(r"CON1  live  connect \S+ ms  TCP only, no banner to check", out)
    kept, = rows("SELECT output FROM results")
    assert json.loads(kept["output"])["port"] == console.port


def test_an_ssh_config_that_cannot_be_read_leaves_the_box_to_the_run(boxes, monkeypatch, tmp_path):
    """Where the ssh configuration cannot say where a box is (a line ssh
    refuses, a Port that is no number), the box is not probed, with the
    words why, and the run finds out what its transport makes of it.
    Without an ssh binary nothing reads the file: the box is asked where it
    is."""
    live = boxes(BANNER)
    if shutil.which("ssh"):
        bad = tmp_path / "ssh_config"
        bad.write_text("Host r1.invalid\n  Bogus yes\n")
        monkeypatch.setattr(probe, "SSH_G", ("ssh", "-F", str(bad), "-G"))
        r, = asyncio.run(probe.probe([Target("R1", "r1.invalid", "openssh")], 3))
        assert r.result == "not probed" and r.reason.startswith("ssh -G r1.invalid: ") and "bogus" in r.reason
    monkeypatch.setattr(probe, "SSH_G", (str(tmp_path / "no-ssh-here"), "-G"))
    r, = asyncio.run(probe.probe([Target("R1", "127.0.0.1", "openssh", live.port)], 3))
    assert (r.result, r.port) == ("live", live.port)
    pyez = tmp_path / "config"
    pyez.write_text("Host r1.invalid\n  Port twenty-two\n")
    monkeypatch.setattr(probe, "SSH_CONFIG", str(pyez))
    r, = asyncio.run(probe.probe([Target("R1", "r1.invalid", "junos")], 3))
    assert (r.result, r.reason) == ("not probed", "~/.ssh/config gives r1.invalid port 'twenty-two'")


# --- the library: Fleet ---------------------------------------------------------------

HOSTS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def _fleet_driver(monkeypatch):
    shown = []

    def show(host, user, passwd, cmd, *a, **kw):
        shown.append(host)
        return f"{cmd} on {host}"

    def show_batch(host, user, passwd, cmds, *a, **kw):
        shown.append(host)
        return [{"command": c, "ok": True, "output": f"{c} on {host}"} for c in cmds]
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, show=show,
                                                                               show_batch=show_batch))
    return shown


def test_a_fleet_probes_before_every_run_and_a_dead_box_is_a_failed_result(monkeypatch):
    shown = _fleet_driver(monkeypatch)
    seen = []
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}, seen=seen))
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        got = {r.device: r for r in fleet.show("show version")}
        assert got["10.0.0.2"].ok is False and got["10.0.0.2"].error == "probe: refused (connection refused by 10.0.0.2:830)"
        assert got["10.0.0.1"].ok and got["10.0.0.3"].ok and sorted(shown) == ["10.0.0.1", "10.0.0.3"]
        got = {r.device: r for r in fleet.batch(["show version", "show route summary"])}
        assert got["10.0.0.2"].ok is False and got["10.0.0.2"].commands == []
        assert got["10.0.0.2"].error.startswith("probe: refused")
    assert sorted(set(seen)) == [("10.0.0.1", 830), ("10.0.0.2", 830), ("10.0.0.3", 830)]
    assert len([s for s in seen if s[0] == "10.0.0.1"]) == 2                 # once per run


def test_fleet_probe_false_skips_it(monkeypatch, probed):
    shown = _fleet_driver(monkeypatch)
    with Fleet(HOSTS, transport="junos", user="u", probe=False) as fleet:
        assert all(r.ok for r in fleet.show("show version"))
    assert probed == [] and sorted(shown) == HOSTS
    with pytest.raises(ValueError, match="probe must be True or False, not 'no'"):
        Fleet(HOSTS, transport="junos", probe="no")


def test_fleet_probe_gives_the_results_as_values_and_keeps_them_in_the_store(monkeypatch, tmp_path):
    monkeypatch.setattr(probe, "attempt", answering(dead={"10.0.0.2"}, slow={"10.0.0.3"}))
    monkeypatch.setattr(probe, "RETRY_PAUSE", 0)
    path = tmp_path / "runs.db"
    with Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:junos", "R3:10.0.0.3:ssh"], user="u", store=str(path)) as fleet:
        got = fleet.probe()
        assert [r.device for r in got] == ["R1", "R2", "R3"] and [r.name for r in got] == ["R1", "R2", "R3"]
        r1, r2, r3 = got
        assert isinstance(r1, probe.ProbeResult)
        assert (r1.host, r1.port, r1.result, r1.connect_ms, r1.banner_ms, r1.banner, r1.reason, r1.slow) == (
            "10.0.0.1", 830, "live", 0.4, 7.2, "SSH-2.0-OpenSSH_9.6", None, None)
        assert (r2.ok, r2.result, r2.reason, r2.banner) == (False, "refused", "connection refused by 10.0.0.2:830", None)
        assert (r3.port, r3.slow) == (22, "slow: answered in 10.7 ms (above 10 ms)")
        assert fleet.probe(slow_ms=25)[2].slow is None
        assert json.loads(json.dumps(r3.to_dict()))["slow"] == r3.slow
        with pytest.raises(ValueError, match="slow_ms must be milliseconds above 0"):
            fleet.probe(slow_ms=0)
    with contextlib.closing(sqlite3.connect(str(path))) as con:
        runs = con.execute("SELECT mode, argv, targets, ok, failed, finished IS NOT NULL FROM runs").fetchall()
        assert runs == [("probe", "Fleet.probe", 3, 2, 1, 1)] * 2
        kept = con.execute("SELECT device, ok, error, format FROM results ORDER BY run_id, device").fetchall()
    assert kept[:3] == [("R1", 1, None, "json"), ("R2", 0, "refused (connection refused by 10.0.0.2:830)", "json"),
                        ("R3", 1, None, "json")]
    with pytest.raises(RuntimeError, match="this Fleet is closed"):
        fleet.probe()


def test_a_fleet_probes_real_boxes(boxes, monkeypatch):
    shown = _fleet_driver(monkeypatch)
    monkeypatch.setitem(drivers.MODULES, "none@ssh", drivers.MODULES["junos@netconf"])
    live = boxes(BANNER)
    dead = refused_port()
    with Fleet([f"R1:127.0.0.1:{live.port}", f"R2:127.0.0.1:{dead}"], user="u", connect_timeout=2) as fleet:
        r1, r2 = fleet.probe()
        assert (r1.result, r1.banner, r2.result) == ("live", "SSH-2.0-OpenSSH_9.6", "refused")
        got = {r.device: r for r in fleet.show("show version")}
    assert got["R1"].ok and got["R2"].error == f"probe: refused (connection refused by 127.0.0.1:{dead})"
    assert shown == ["127.0.0.1"]


def test_a_fleet_with_a_name_no_resolver_takes_runs_the_others(boxes, monkeypatch):
    """`10.0.0..1` is one failed result, name not found, and the rest of
    the fleet runs; probe() gives it as a value, not an exception."""
    shown = _fleet_driver(monkeypatch)
    live = boxes(BANNER)
    with Fleet(["R1:10.0.0..1:junos", f"R2:127.0.0.1:{live.port}:junos"], user="u", connect_timeout=2) as fleet:
        r1, r2 = fleet.probe()
        assert (r1.result, r2.result) == ("name not found", "live") and "label empty" in r1.reason
        got = {r.device: r for r in fleet.show("show version")}
        assert got["R1"].ok is False and got["R1"].error.startswith("probe: name not found (cannot resolve 10.0.0..1: ")
        assert got["R2"].ok and shown == ["127.0.0.1"]
        got = {r.device: r for r in fleet.batch(["show version"])}
        assert got["R1"].ok is False and got["R2"].ok


def test_a_close_during_the_probe_ends_the_run_at_once(monkeypatch, tmp_path):
    """The probe is waited for off the run's lock: a close() from another
    thread wakes the show() at once, which fails as on a closed Fleet, and
    the run row says every device was skipped."""
    _fleet_driver(monkeypatch)

    async def slow_to_answer(host, port, banner, seconds):
        await asyncio.sleep(3)
        return probe.Answer(probe.LIVE, None, 0.4, 7.2, "SSH-2.0-x")
    monkeypatch.setattr(probe, "attempt", slow_to_answer)
    path = tmp_path / "runs.db"
    fleet = Fleet(HOSTS, transport="junos", user="u", store=str(path))
    threading.Timer(0.3, fleet.close).start()
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="this Fleet is closed"):
        fleet.show("show version")
    assert time.monotonic() - started < 2.0
    with contextlib.closing(sqlite3.connect(str(path))) as con:
        assert con.execute("SELECT ok, failed, skipped, interrupted FROM runs").fetchall() == [(0, 0, 3, 1)]


@pytest.mark.parametrize("err, limit", [(errno.EMFILE, "ulimit -n"), (errno.ENFILE, "fs.file-max")])
def test_a_box_this_machine_has_no_descriptor_for_is_not_probed_not_dead(real_probe, monkeypatch, err, limit):
    """#147 live check: a Fleet holding a pooled session for each of 250
    routers at an open-file limit of 256 probed its second run with no
    descriptor to spare, and every box whose socket() failed with EMFILE was
    called dead ('no route ... Too many open files'), 110 of them. That is
    this machine, not the box: it is not probed, and runs as under
    --no-probe."""
    real = socket.socket

    def no_descriptor(family=-1, type=-1, proto=-1, fileno=None):
        if fileno is None and family in (socket.AF_INET, socket.AF_INET6):   # the probe's, not the loop's own
            raise OSError(err, os.strerror(err))
        return real(family, type, proto, fileno)
    monkeypatch.setattr(probe.socket, "socket", no_descriptor)
    answer = asyncio.run(probe.attempt("127.0.0.1", 830, b"SSH-", 1.0))
    assert answer.result == probe.NOT_PROBED and limit in answer.reason, answer



def test_ssh_g_runs_without_the_operators_password_in_its_environment(monkeypatch, tmp_path):
    """#151: the probe's `ssh -G` ran with the environment as it is,
    HSSH_PASSWORD in it, where the openssh transport keeps the variable
    from every ssh it runs."""
    fake = tmp_path / "ssh"
    fake.write_text("#!/bin/sh\nenv > \"$FAKE_SSH_ENV\"\nprintf 'hostname 127.0.0.1\\nport 22\\n'\n")
    fake.chmod(0o700)
    monkeypatch.setenv("FAKE_SSH_ENV", str(tmp_path / "env"))
    monkeypatch.setenv("HSSH_PASSWORD", "hunter2")
    monkeypatch.setattr(probe, "SSH_G", (str(fake), "-G"))
    route = probe._ssh_g("r1.invalid", None, 22, "u", 5)
    assert (route.host, route.port, route.via) == ("127.0.0.1", 22, None)
    seen = (tmp_path / "env").read_text()
    assert "hunter2" not in seen and "HSSH_PASSWORD" not in seen and "FAKE_SSH_ENV" in seen
