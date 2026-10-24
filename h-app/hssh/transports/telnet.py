"""The telnet channel: a raw socket with the option negotiation answered,
for the CLI engine to type at. Frozen (2026-10-24): the legacy fallback,
it inherits dialects and fixes and gets nothing of its own.

Raw sockets instead of telnetlib (deprecated in Python 3.11, removed in 3.13).
"""

import socket
import time


def negotiate(sock: socket.socket) -> str:
    """Handle basic telnet IAC negotiation. Returns any non-IAC data as string."""
    try:
        sock.setblocking(False)
        time.sleep(0.3)
        try:
            data = sock.recv(4096)
        except (BlockingIOError, socket.error):
            data = b""
        sock.setblocking(True)
        i = 0
        responses = bytearray()
        non_iac = bytearray()
        while i < len(data):
            if data[i] == 0xFF and i + 2 < len(data):  # IAC
                cmd = data[i + 1]
                opt = data[i + 2]
                if cmd == 0xFB:    # WILL -> DONT
                    responses.extend([0xFF, 0xFE, opt])
                elif cmd == 0xFD:  # DO -> WONT
                    responses.extend([0xFF, 0xFC, opt])
                i += 3
            else:
                non_iac.append(data[i])
                i += 1
        if responses:
            sock.sendall(bytes(responses))
        return non_iac.decode("utf-8", errors="replace") if non_iac else ""
    except Exception:
        return ""
    finally:
        if sock:
            sock.setblocking(True)


class TelnetChannel:
    """A connected telnet socket as the engine's Channel: recv(n, timeout)
    raises TimeoutError when nothing arrived in time and ConnectionError when
    the socket failed; an empty read is the peer closing, which the engine
    reports. `initial` is what the device sent during negotiation."""

    def __init__(self, sock: socket.socket, initial: str = ""):
        self.sock = sock
        self.initial = initial

    @classmethod
    def connect(cls, host: str, port: int, timeout: int) -> "TelnetChannel":
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return cls(sock, negotiate(sock))

    def recv(self, n: int, timeout: float) -> bytes:
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(n)
        except TimeoutError:          # socket.timeout since Python 3.10
            raise
        except OSError as e:
            raise ConnectionError(f"connection lost: {e}") from e

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
