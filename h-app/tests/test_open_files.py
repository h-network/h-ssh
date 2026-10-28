"""#147: the open-file limit, with real NETCONF sessions and real descriptors.
A Fleet keeps a NETCONF session per junos device for its life, and a --job
one per device while it has entries left, ~4 descriptors each beside the
workers'. Each test here runs h-ssh in a child process whose RLIMIT_NOFILE
is lowered first, against a fake NETCONF-over-SSH server on 127.0.0.1 in
this one (one port per router, any password, an rpc-reply to anything):
nothing else is contacted."""
import json
import logging
import os
import re
import selectors
import socket
import subprocess
import sys
import threading

import pytest

resource = pytest.importorskip("resource")

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_HELLO = (b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>'
          b'<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>'
          b'<session-id>1</session-id></hello>]]>]]>')

_FLEET = r"""
import json, resource, sys, warnings
soft, hard, ports = int(sys.argv[1]), int(sys.argv[2]), json.loads(sys.argv[3])
resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
from hssh import Fleet, pool
targets = [f"r{i}:127.0.0.1:junos:{port}" for i, port in enumerate(ports)]
out = {}
with warnings.catch_warnings(record=True) as said:
    warnings.simplefilter("always")
    with Fleet(targets, user="u", passwd="p", workers=4, probe=False, session_timeout=20,
               command_timeout=20) as fleet:
        out["runs"] = [[[r.device, r.ok, r.error] for r in fleet.show("show version")] for _ in range(2)]
        out["stats"] = dict(pool.POOL.stats)
out["warnings"] = [str(w.message) for w in said]
out["limit"] = list(resource.getrlimit(resource.RLIMIT_NOFILE))
print(json.dumps(out))
"""

_JOB = r"""
import json, os, resource, sys
soft, hard, ports = int(sys.argv[1]), int(sys.argv[2]), json.loads(sys.argv[3])
resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
job = os.path.join(os.environ["HOME"], "job.json")
with open(job, "w") as f:
    json.dump([{"target": f"r{i}:127.0.0.1:junos:{port}", "show": "show version"} for i, port in enumerate(ports)], f)
from hssh import cli
sys.argv = ["h-ssh", "--config", os.devnull, "--user", "u", "--job", job, "--json", "--no-store", "--workers", "4"]
cli.main_sync()
"""


@pytest.fixture
def routers():
    """routers(n) -> n ports on 127.0.0.1, each a NETCONF router that lets
    anyone in with a password and answers every RPC; closed after the test."""
    paramiko = pytest.importorskip("paramiko")
    pytest.importorskip("jnpr.junos")
    key = paramiko.ECDSAKey.generate()
    listeners, transports, stop = [], [], threading.Event()
    sel = selectors.DefaultSelector()
    quiet = logging.getLogger("paramiko")
    level = quiet.level
    quiet.setLevel(logging.CRITICAL + 1)   # the probe's connections end before a client banner, as they should

    def netconf(chan):
        try:
            chan.sendall(_HELLO)
            pending = b""
            while True:
                data = chan.recv(65536)
                if not data:
                    return
                pending += data
                while b"]]>]]>" in pending:
                    message, pending = pending.split(b"]]>]]>", 1)
                    mid = re.search(rb'message-id="([^"]+)"', message)
                    if mid is None:
                        continue                         # the client's hello
                    reply = (b'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="'
                             + mid.group(1) + b'">')
                    if b"close-session" in message:
                        chan.sendall(reply + b"<ok/></rpc-reply>]]>]]>")
                        chan.close()
                        return
                    chan.sendall(reply + b"<output>fake version</output></rpc-reply>]]>]]>")
        except Exception:
            return

    class Router(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_subsystem_request(self, channel, name):
            if name != "netconf":
                return False
            threading.Thread(target=netconf, args=(channel,), daemon=True).start()
            return True

    def serve(conn):
        t = paramiko.Transport(conn)
        t.add_server_key(key)
        transports.append(t)
        try:
            t.start_server(server=Router())
        except Exception:
            conn.close()

    def accept():
        while not stop.is_set():
            for found, _ in sel.select(0.2):
                try:
                    conn, _ = found.fileobj.accept()
                except OSError:
                    continue
                conn.setblocking(True)
                threading.Thread(target=serve, args=(conn,), daemon=True).start()

    def make(n):
        ports = []
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            s.listen(16)
            s.setblocking(False)
            sel.register(s, selectors.EVENT_READ)
            listeners.append(s)
            ports.append(s.getsockname()[1])
        threading.Thread(target=accept, daemon=True).start()
        return ports
    yield make
    stop.set()
    for t in transports:
        t.close()
    for s in listeners:
        s.close()
    quiet.setLevel(level)


def _child(tmp_path, script, soft, hard, ports, **env):
    """`script` in a child process with RLIMIT_NOFILE (soft, hard): its
    return code, stdout and stderr. HOME is the test's own directory, so no
    ~/.ssh/config or ~/.h-ssh of the user's is read."""
    path = tmp_path / "child.py"
    path.write_text(script)
    clean = {k: v for k, v in os.environ.items() if not k.startswith("HSSH_")}
    clean.update(PYTHONPATH=APP, HOME=str(tmp_path), **env)
    proc = subprocess.run([sys.executable, str(path), str(soft), str(hard), json.dumps(ports)],
                          env=clean, capture_output=True, text=True, timeout=180)
    return proc.returncode, proc.stdout, proc.stderr


def _hard():
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    return 1 << 20 if hard == resource.RLIM_INFINITY else hard


# Four workers at ~6 descriptors and the base of 32 leave a soft limit of 80
# room for 6 sessions of ~4; 24 routers are four times that.
SOFT, ROUTERS, WORKERS = 80, 24, 4


def test_a_fleet_keeps_a_session_for_every_router_the_soft_limit_had_no_room_for(routers, tmp_path):
    """The fit counted the workers alone, so the soft limit was left at 80:
    19 of 24 routers answered, 5 failed with "Too many open files", some of
    them said as "connection refused". It is raised for the sessions now."""
    ports = routers(ROUTERS)
    rc, out, err = _child(tmp_path, _FLEET, SOFT, _hard(), ports)
    assert rc == 0, err
    done = json.loads(out)
    for run in done["runs"]:
        assert [r for r in run if not r[1]] == [] and len(run) == ROUTERS
    assert done["limit"][0] >= WORKERS * 6 + ROUTERS * 4 + 32
    assert done["stats"]["opens"] == ROUTERS and done["stats"]["reaped"] == 0     # every session kept
    assert done["warnings"] == []


def test_a_fleet_whose_hard_limit_cannot_hold_its_sessions_closes_idle_ones_rather_than_fail(routers, tmp_path):
    """With the hard limit at 80 too, nothing can be raised: the pool closes
    its least recently used idle sessions before it opens more, every router
    answers both runs, and the warning says how many sessions it keeps."""
    ports = routers(ROUTERS)
    rc, out, err = _child(tmp_path, _FLEET, SOFT, SOFT, ports)
    assert rc == 0, err
    done = json.loads(out)
    for run in done["runs"]:
        assert [r for r in run if not r[1]] == [] and len(run) == ROUTERS
    assert done["limit"] == [SOFT, SOFT] and done["stats"]["reaped"] > 0
    assert done["warnings"] == [
        "the open-file limit of 80 (ulimit -n) keeps 6 of the 24 pooled sessions open at ~4 descriptors each: "
        "the least recently used idle one is closed when another must open, and opened again when it is wanted"]


def test_a_job_lets_each_routers_session_go_after_its_last_entry(routers, tmp_path):
    """A job kept every session to the end of the run: 18 of 24 routers
    answered at a soft limit of 80, 6 failed with "Too many open files"."""
    ports = routers(ROUTERS)
    rc, out, err = _child(tmp_path, _JOB, SOFT, _hard(), ports, HSSH_PASSWORD="p")
    assert rc == 0, err
    results = json.loads(out)
    assert len(results) == ROUTERS and [r for r in results if not r["ok"]] == []
