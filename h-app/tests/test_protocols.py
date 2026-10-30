import pytest

from hssh.communicators.base import Communicator
from hssh.communicators.netconf import NetconfCommunicator
from hssh.communicators.openssh import OpenSSH
from hssh.communicators.ssh import SSHCommunicator
from hssh.communicators.telnet import TelnetCommunicator
from hssh.dialects import generic, junos
from hssh.dialects.base import Dialect

COMMUNICATOR_MEMBERS = {"capabilities", "dialect", "default_port", "banner", "open", "close", "show", "structured",
                        "load", "diff", "commit", "confirm", "commit_history"}
DIALECT_MEMBERS = {"prompt_pattern", "paging_off_command", "refusal_patterns", "warning_patterns",
                   "config_enter_command", "config_exit_command", "commit_command", "discard_commands",
                   "has_candidate", "redaction_patterns", "comment_prefixes", "is_read", "check_edit"}


def test_the_communicator_protocol_is_section_4_1_with_no_rollback():
    assert set(Communicator.__protocol_attrs__) == COMMUNICATOR_MEMBERS


def test_the_dialect_protocol_is_section_3_5_plus_the_edit_hooks():
    assert set(Dialect.__protocol_attrs__) == DIALECT_MEMBERS


@pytest.mark.parametrize("make", [NetconfCommunicator, OpenSSH, SSHCommunicator, TelnetCommunicator])
def test_every_built_in_communicator_has_each_protocol_member(make):
    communicator = make(junos.DIALECT)
    missing = {m for m in COMMUNICATOR_MEMBERS if not hasattr(communicator, m)}
    assert missing == set()
    assert communicator.dialect is junos.DIALECT and isinstance(communicator.default_port, int)


@pytest.mark.parametrize("dialect", [generic.DIALECT, junos.DIALECT])
def test_every_built_in_dialect_has_each_protocol_member(dialect):
    assert {m for m in DIALECT_MEMBERS if not hasattr(dialect, m)} == set()
