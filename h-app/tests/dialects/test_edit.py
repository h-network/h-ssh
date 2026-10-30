import pytest

from hssh.dialects import eos, generic, ios, junos, nxos


@pytest.mark.parametrize('lines', [[], [''], ['   '], ['# note', '   # next', '']])
def test_empty_or_comment_only_edit_is_refused(dialect, lines):
    assert dialect.check_edit(lines) == 'configuration payload contains no commands'


@pytest.mark.parametrize('dialect,prefixes', [
    (generic.DIALECT, ('#',)), (junos.DIALECT, ('#',)),
    (ios.DIALECT, ('#', '!')), (nxos.DIALECT, ('#', '!')), (eos.DIALECT, ('#', '!')),
])
def test_comment_prefixes_follow_the_vendor(dialect, prefixes):
    assert dialect.comment_prefixes == prefixes


def test_ios_comment_only_edit_is_refused(ios_dialect):
    assert ios_dialect.check_edit([' ! note', '# note', '']) is not None


def test_generic_bang_line_is_a_command():
    assert generic.DIALECT.check_edit(['! command']) is None


def test_junos_bang_line_is_invalid_configuration():
    refusal = junos.DIALECT.check_edit(['# note', '! note'])
    assert refusal.startswith('line 2: invalid Junos set command:')
    assert repr('! note') in refusal


@pytest.mark.parametrize('verb', [
    'set', 'delete', 'activate', 'deactivate', 'insert',
    'rename', 'copy', 'annotate', 'protect', 'unprotect',
])
def test_junos_accepts_lowercase_set_style_verbs(verb):
    assert junos.DIALECT.check_edit([verb + ' system host-name example']) is None


@pytest.mark.parametrize('line', [
    'commit', 'commit;', 'commit;; and-quit', 'commit confirmed 5',
    'com', 'comm', 'commi;', 'com confirmed 1',
])
def test_junos_refuses_embedded_commit_and_unique_abbreviations(line):
    refusal = junos.DIALECT.check_edit(['# note', 'set system host-name example', line])
    assert refusal.startswith('line 3: commit is not permitted')
    assert repr(line) in refusal


def test_standalone_commit_is_not_a_payload():
    assert junos.DIALECT.check_edit(['commit']) is not None


@pytest.mark.parametrize('line', ['SET system host-name x', 'set', 'configure', 'system {', 'co a', 'committed'])
def test_junos_requires_a_full_lowercase_set_verb(line):
    refusal = junos.DIALECT.check_edit(['', '# note', line])
    assert refusal.startswith('line 3: invalid Junos set command:')
    assert repr(line) in refusal


@pytest.mark.parametrize('line', [
    'set system host-name x\x03commit comment y', 'set a\x15commit',
    'set ' + '\x7f' * 4 + 'commit', 'set a\x1b[2Kcommit',
    'set a\x9b2Kcommit', 'set a\x00commit', 'set a\x85commit',
    'set a\rcommit', 'set a\ncommit', 'set a\udcffb',
])
def test_junos_refuses_control_characters_and_surrogates(line):
    refusal = junos.DIALECT.check_edit(['# note', line])
    assert refusal.startswith('line 2: control characters')
    assert repr(line) in refusal


@pytest.mark.parametrize('line', [
    '\tset system host-name x', 'set system\thost-name x', 'set system host-name x\t',
    'set system login announcement "a\tb"', 'commit\tcomment x', '\t',
])
def test_junos_refuses_tab_before_stripping_whitespace(line):
    refusal = junos.DIALECT.check_edit(['set system host-name example', line])
    assert refusal.startswith('line 2: control characters and Tab')


def test_comments_and_inline_hashes_do_not_change_the_payload(dialect):
    lines = ['# note', '', 'set system login announcement "a # b"', 'set system host-name café']
    original = lines.copy()
    assert dialect.check_edit(lines) is None
    assert lines == original


def test_refusal_does_not_change_the_payload():
    lines = ['# note', 'set system host-name example', 'commit;']
    original = lines.copy()
    assert junos.DIALECT.check_edit(lines) is not None
    assert lines == original


def test_commit_words_inside_configuration_are_values():
    assert junos.DIALECT.check_edit([
        'set system commit synchronize', 'set system login announcement "commit; com # inline"',
    ]) is None


def test_junos_skips_controls_in_comments_that_will_not_be_sent():
    assert junos.DIALECT.check_edit(['\t# note\x03', 'set system host-name example']) is None
