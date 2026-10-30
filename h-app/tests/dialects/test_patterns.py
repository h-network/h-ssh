import pytest

from hssh.dialects import generic, junos


@pytest.mark.parametrize('prompt', ['lab@r1> ', 'lab@r1# ', 'lab@r1%', 'lab@r1.example>\r\n'])
def test_junos_prompt_shape(prompt):
    assert junos.DIALECT.prompt_pattern.search(prompt)


@pytest.mark.parametrize('output', ['Router#', 'lab@r1> show version', 'Hostname: r1', 'error: syntax error'])
def test_junos_ordinary_output_is_not_a_prompt(output):
    assert junos.DIALECT.prompt_pattern.search(output) is None


@pytest.mark.parametrize('prompt', ['Router>', 'Router#', 'Router(config)#', 'Switch(config-if-Et1/1)# '])
def test_ios_prompt_shape(ios_dialect, prompt):
    assert ios_dialect.prompt_pattern.search(prompt)


@pytest.mark.parametrize('prompt', ['Router>', 'Router(config)#'])
def test_generic_prompt_shape(prompt):
    assert generic.DIALECT.prompt_pattern.search(prompt)


@pytest.mark.parametrize('line', [
    'error: syntax error', '  syntax error, expecting <command>', 'commit failed: x',
    'unknown command', 'missing argument', 'ERROR: configuration database locked',
])
def test_junos_refusal_starts_a_line(line):
    assert any(p.search('output\n' + line + '\nmore') for p in junos.DIALECT.refusal_patterns)


@pytest.mark.parametrize('line', ['description error-disabled', 'description error: x', '% Invalid input', 'commit complete'])
def test_junos_output_is_not_a_refusal(line):
    assert not any(p.search(line) for p in junos.DIALECT.refusal_patterns)


@pytest.mark.parametrize('line', ['error: syntax error', '  % Invalid input'])
def test_generic_recognises_both_refusal_forms(line):
    assert any(p.search(line) for p in generic.DIALECT.refusal_patterns)


@pytest.mark.parametrize('line', [
    "% Invalid input detected at '^' marker.", '%Inconsistent address and mask',
    '%Error opening flash:x.cfg (No such file or directory)',
    'ERROR: The secret you entered is not a valid encrypted secret.',
    'ERROR: VLAN 4095 is a reserved VLAN', '% Incomplete command.',
    '% Ambiguous command: "sh"', '% Interface Gi0/9 not found', '% Warnings are disabled',
])
def test_ios_refusals_are_not_warning_lines(ios_dialect, line):
    assert any(p.search('\n' + line + '\nmore') for p in ios_dialect.refusal_patterns)
    assert not any(p.search(line) for p in ios_dialect.warning_patterns)


@pytest.mark.parametrize('line', [
    '%Warning: portfast should only be enabled on ports connected to a single',
    '% Warning: use /31 mask on non point-to-point interface cautiously', '% WARNING: low memory',
    '% Interface GigabitEthernet0/1 IPv4 disabled and address(es) removed due to enabling VRF CUST',
    '  % Interface Gi0/2 IPv4 disabled and address(es) removed due to disabling VRF CUST',
    '%Portfast has been configured on GigabitEthernet0/1 but will only',
    '%Portfast will be configured in 10 interfaces due to the range command',
    '%Default route without gateway, if not a point-to-point interface, may impact performance',
    '%Command accepted but obsolete, unreleased or unsupported; see documentation.',
    '% The key modulus size is 2048 bits',
    '% Generating 2048 bit RSA keys, keys will be non-exportable...',
    '% Applying VLAN changes may take few minutes.  Please wait...',
])
def test_ios_accepted_line_notes_have_warning_patterns(ios_dialect, line):
    assert any(p.search('\n' + line + '\n') for p in ios_dialect.warning_patterns)


@pytest.mark.parametrize('line', [
    '%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up',
    '%OIR-SP-6-INSCARD: Card inserted in slot 3, interfaces are now online',
    '%SYS-5-CONFIG_I: Configured from console',
    '%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success',
    '%ETHPORT-5-IF_UP: Interface Ethernet1/1 is up',
    '100% of the table in use', 'Errors: 0', 'error: syntax error',
])
def test_ios_syslog_and_ordinary_output_are_not_refusals(ios_dialect, line):
    assert not any(p.search(line) for p in ios_dialect.refusal_patterns)
    assert not any(p.search(line) for p in ios_dialect.warning_patterns)


@pytest.mark.parametrize('command', ['show', ' SHOW version ', 'get', 'get interfaces'])
def test_read_commands_are_recognised(dialect, command):
    assert dialect.is_read(command)


@pytest.mark.parametrize('command', ['', 'showcase', 'configure', 'set system host-name x', 'commit', 'reload'])
def test_write_commands_are_not_reads(dialect, command):
    assert not dialect.is_read(command)


def test_junos_candidate_commands_use_exclusive_mode_and_discard_only_uncommitted_changes():
    assert junos.DIALECT.has_candidate
    assert junos.DIALECT.config_enter_command == 'configure exclusive'
    assert junos.DIALECT.config_exit_command == 'exit'
    assert junos.DIALECT.commit_command == 'commit'
    assert junos.DIALECT.discard_commands == ('rollback 0',)


def test_ios_configuration_has_no_candidate_commit(ios_dialect):
    assert not ios_dialect.has_candidate
    assert ios_dialect.config_enter_command == 'configure terminal'
    assert ios_dialect.config_exit_command == 'end'
    assert ios_dialect.commit_command is None
    assert ios_dialect.discard_commands == ()
