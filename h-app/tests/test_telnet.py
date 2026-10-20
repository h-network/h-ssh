"""Telnet transport tests — mock socket server, no live devices needed."""
import json
import socket
import subprocess
import sys
import os
import threading
import time
import pytest

HSSH = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
CWD = os.path.join(os.path.dirname(__file__), "..")


class MockTelnetServer:
    """Minimal mock telnet server for testing."""

    def __init__(self, vendor="ios"):
        self.vendor = vendor
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                self.server.settimeout(1.0)
                conn, _ = self.server.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn: socket.socket):
        try:
            conn.settimeout(10.0)
            if self.vendor == "ios":
                prompt = "Router#"
            elif self.vendor == "junos":
                prompt = "user@Router>"
            elif self.vendor == "arista":
                prompt = "Switch#"
            else:
                prompt = "Router#"

            conn.sendall(f"\r\n{prompt} ".encode())

            while True:
                try:
                    data = conn.recv(4096).decode("utf-8", errors="replace").strip()
                    if not data:
                        continue

                    if data == "show version":
                        response = f"Mock {self.vendor} device\nVersion: 1.0.0\nUptime: 1 day\r\n{prompt} "
                    elif data == "show ip route":
                        response = f"Gateway of last resort is 10.0.0.1\n10.0.0.0/24 is directly connected\n192.168.1.0/24 via 10.0.0.1\r\n{prompt} "
                    elif data == "show interfaces":
                        response = f"GigabitEthernet0/0 is up, line protocol is up\n  Internet address is 10.0.0.1/24\r\n{prompt} "
                    elif data.startswith("configure") or data == "conf t":
                        response = f"Entering configuration mode\r\n{prompt.replace('#', '(config)#').replace('>', '#')} "
                    elif data == "end":
                        response = f"\r\n{prompt} "
                    elif data == "exit":
                        response = f"\r\n{prompt} "
                    elif data.startswith("set ") or data.startswith("interface ") or data.startswith("ip "):
                        response = f"\r\n{prompt.replace('#', '(config)#').replace('>', '#')} "
                    elif data == "show | compare":
                        response = f"[edit system]\n+  host-name test;\r\n{prompt.replace('>', '#')} "
                    elif data.startswith("rollback"):
                        response = f"Rolled back\r\n{prompt.replace('>', '#')} "
                    elif data == "commit":
                        response = f"commit complete\r\n{prompt.replace('>', '#')} "
                    else:
                        response = f"% Unknown command: {data}\r\n{prompt} "

                    conn.sendall(response.encode())
                except socket.timeout:
                    break
                except (ConnectionError, OSError):
                    break
        finally:
            conn.close()

    def stop(self):
        self._running = False
        self.server.close()


@pytest.fixture(scope="module")
def ios_server():
    server = MockTelnetServer(vendor="ios")
    yield server
    server.stop()


@pytest.fixture(scope="module")
def junos_server():
    server = MockTelnetServer(vendor="junos")
    yield server
    server.stop()


@pytest.fixture(scope="module")
def arista_server():
    server = MockTelnetServer(vendor="arista")
    yield server
    server.stop()


# ---- Unit tests for ANSI stripping ----

def test_ansi_strip():
    """ANSI escape codes are stripped from output."""
    from hssh.vendors.telnet import _strip_ansi

    assert _strip_ansi("\x1b[32mgreen\x1b[0m") == "green"
    assert _strip_ansi("no escapes here") == "no escapes here"
    assert _strip_ansi("\x1b[1;31mred bold\x1b[0m text") == "red bold text"


# ---- Functional tests via mock telnet ----

def test_ios_show_version(ios_server):
    """Show command via IOS telnet returns device output."""
    from hssh.vendors.telnet import show
    result = show("127.0.0.1", "admin", "admin", "show version",
                  session_timeout=5, command_timeout=5,
                  port=ios_server.port, vendor_hint="telnet-ios")
    assert "Mock ios device" in result
    assert "Version: 1.0.0" in result


def test_ios_show_ip_route(ios_server):
    """Show ip route via IOS telnet."""
    from hssh.vendors.telnet import show
    result = show("127.0.0.1", "admin", "admin", "show ip route",
                  session_timeout=5, command_timeout=5,
                  port=ios_server.port, vendor_hint="telnet-ios")
    assert "10.0.0" in result


def test_arista_show_interfaces(arista_server):
    """Show interfaces via Arista telnet."""
    from hssh.vendors.telnet import show
    result = show("127.0.0.1", "admin", "admin", "show interfaces",
                  session_timeout=5, command_timeout=5,
                  port=arista_server.port, vendor_hint="telnet-arista")
    assert "GigabitEthernet" in result


def test_show_batch(ios_server):
    """Multiple commands on a single connection."""
    from hssh.vendors.telnet import show_batch
    results = show_batch("127.0.0.1", "admin", "admin",
                         ["show version", "show ip route"],
                         session_timeout=5, command_timeout=5,
                         port=ios_server.port, vendor_hint="telnet-ios")
    assert len(results) == 2
    assert all(r["ok"] for r in results)
    assert "Mock ios device" in results[0]["output"]
    assert "10.0.0" in results[1]["output"]


def test_telnet_always_available():
    """Raw socket telnet is always available (no external deps)."""
    from hssh.vendors.telnet import AVAILABLE
    assert AVAILABLE is True
