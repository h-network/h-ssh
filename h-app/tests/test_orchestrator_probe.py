import asyncio
import socket

import pytest

from hssh.model import FaultKind, Target
from hssh.orchestrator import probe

T = Target("r1", "127.0.0.1", "junos", "netconf")


FINISHED = None


async def with_server(handler, body):
    """A local TCP server for one probe; a handler that waits on FINISHED is released once the body is done."""
    global FINISHED
    FINISHED = asyncio.Event()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        return await body(port)
    finally:
        FINISHED.set()
        server.close()
        await server.wait_closed()


def banner_server(lines):
    async def handler(reader, writer):
        for line in lines:
            writer.write(line)
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
    return handler


def closes_at_once(reader, writer):
    writer.close()


async def says_nothing(reader, writer):
    await FINISHED.wait()
    writer.close()


def attempt(handler, banner=b"SSH-", seconds=0.3):
    return asyncio.run(with_server(handler, lambda port: probe.attempt("127.0.0.1", port, banner, seconds)))


def test_a_box_that_sends_its_identification_is_live():
    assert attempt(banner_server([b"SSH-2.0-OpenSSH_9.6\r\n"])) is None


def test_lines_before_the_identification_are_passed_over():
    assert attempt(banner_server([b"Welcome\r\n", b"to this box\r\n", b"SSH-2.0-x\r\n"])) is None


def test_more_than_a_hundred_lines_before_the_identification_is_not_an_ssh_server():
    fault = attempt(banner_server([b"noise\r\n"] * 101 + [b"SSH-2.0-x\r\n"]))
    assert fault.kind is FaultKind.UNREACHABLE and fault.reached_device and b"noise" in fault.detail.encode()


def test_a_line_over_255_bytes_is_not_an_ssh_server():
    fault = attempt(banner_server([b"x" * 300 + b"\r\n", b"SSH-2.0-x\r\n"]))
    assert fault.kind is FaultKind.UNREACHABLE and fault.reached_device


def test_a_box_that_answers_something_else_is_dead_and_the_answer_is_quoted():
    fault = attempt(banner_server([b"220 mail ready\r\n"]))
    assert fault.kind is FaultKind.UNREACHABLE and fault.reached_device and "220 mail ready" in fault.detail


def test_a_box_that_closes_without_a_line_is_dead_but_was_reached():
    fault = attempt(closes_at_once)
    assert fault.kind is FaultKind.UNREACHABLE and fault.reached_device and "closed without" in fault.detail


def test_a_box_that_accepts_tcp_but_says_nothing_times_out_as_reached():
    fault = attempt(says_nothing, seconds=0.2)
    assert fault.kind is FaultKind.UNREACHABLE and fault.reached_device and "within 0.2s" in fault.detail


def test_a_protocol_without_a_banner_is_asked_tcp_alone():
    assert attempt(says_nothing, banner=None) is None


def test_nothing_listening_is_unreachable_and_reached_nothing():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    fault = asyncio.run(probe.attempt("127.0.0.1", port, b"SSH-", 0.5))
    assert fault.kind is FaultKind.UNREACHABLE and not fault.reached_device


def test_a_name_no_resolver_takes_is_unreachable_and_says_so():
    fault = asyncio.run(probe.attempt("no-such-host.invalid", 22, b"SSH-", 2))
    assert fault.kind is FaultKind.UNREACHABLE and "cannot resolve" in fault.detail


def test_probe_maps_every_box_to_its_result_and_a_live_one_to_none():
    async def go():
        return await with_server(banner_server([b"SSH-2.0-x\r\n"]), lambda port: probe.probe(
            [(T, "127.0.0.1", port, b"SSH-"), (Target("r2", "h", "junos", "netconf"), "no-such-host.invalid", 22, b"SSH-")],
            2))

    result = asyncio.run(go())
    assert result["r1"] is None and result["r2"].kind is FaultKind.UNREACHABLE


@pytest.fixture
def ssh_config(tmp_path, monkeypatch):
    path = tmp_path / "config"
    monkeypatch.setattr(probe, "SSH_CONFIG", path)
    return path


def test_the_probe_goes_where_ssh_config_sends_the_connection(ssh_config):
    ssh_config.write_text("Host r1\n  HostName 10.9.9.9\n  Port 2222\n")
    assert probe.route("r1", None, 830) == ("10.9.9.9", 2222)


def test_the_targets_own_port_wins_over_ssh_config(ssh_config):
    ssh_config.write_text("Host r1\n  Port 2222\n")
    assert probe.route("r1", 830, 22) == ("r1", 830)


def test_a_proxied_box_is_not_probed(ssh_config):
    ssh_config.write_text("Host r1\n  ProxyJump bastion\nHost r2\n  ProxyCommand nc %h %p\n")
    assert probe.route("r1", None, 22) is None and probe.route("r2", None, 22) is None


def test_without_an_ssh_config_the_box_is_probed_at_its_address_and_the_transports_port(ssh_config):
    assert probe.route("10.0.0.1", None, 830) == ("10.0.0.1", 830)
    assert probe.route("10.0.0.1", 22, 830) == ("10.0.0.1", 22)
