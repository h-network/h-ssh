"""#194: the suite runs with a scratch HOME, never the operator's.

First contact pins host keys into ~/.h-ssh/known_hosts (the ssh
transport's `_known_hosts`) and the openssh transport reads ~/.ssh/config.
Before `_home_in_tmp` in conftest.py, a test that did not ask for a home
of its own let those read and write the operator's real home. The autouse
fixture gives every test a scratch HOME and fails a test that still
touches the real one; these tests pin down the guarantee itself.
"""

import os
from pathlib import Path

from hssh.transports import ssh as _ssh

_REAL_HOME = os.path.expanduser("~")
_REAL_HOME_DIRS = (
    os.path.join(_REAL_HOME, ".h-ssh"),
    os.path.join(_REAL_HOME, ".ssh"),
)


def _real_home_state():
    """The real home's dot-directories, as a comparable state: path-relative
    names with size and mtime, or None where a directory does not exist."""
    state = []
    for root in _REAL_HOME_DIRS:
        if not os.path.isdir(root):
            state.append((root, None))
            continue
        seen = []
        for dirpath, dirnames, filenames in os.walk(root):
            for name in sorted(dirnames + filenames):
                path = os.path.join(dirpath, name)
                st = os.lstat(path)
                seen.append((os.path.relpath(path, root), st.st_size, st.st_mtime_ns))
        state.append((root, sorted(seen)))
    return state


def _under_a_real_dot_dir(path: Path) -> bool:
    """True when `path` is the real ~/.h-ssh or ~/.ssh or something inside
    them -- the directories #194 polluted and the suite must not touch."""
    candidate = os.path.normcase(os.path.abspath(str(path)))
    for root in _REAL_HOME_DIRS:
        root = os.path.normcase(os.path.abspath(root))
        if candidate == root or candidate.startswith(root + os.sep):
            return True
    return False


def test_the_pin_file_lives_in_the_scratch_home_not_the_real_one():
    """#194's pollution: first contact creates ~/.h-ssh/known_hosts. It must
    be this test's scratch HOME, and the real ~/.h-ssh and ~/.ssh must be
    left exactly as they were."""
    before = _real_home_state()
    pin = Path(_ssh._known_hosts())
    assert os.path.normcase(str(pin)) == os.path.normcase(
        str(Path.home() / ".h-ssh" / "known_hosts")
    )
    assert not _under_a_real_dot_dir(pin)
    assert _real_home_state() == before


def test_the_scratch_home_is_never_the_real_home():
    assert os.path.normcase(str(Path.home())) != os.path.normcase(_REAL_HOME)
    assert not _under_a_real_dot_dir(Path.home())
