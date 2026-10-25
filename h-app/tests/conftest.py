"""Every run is kept in a store (hssh.store), h-ssh.db in the current directory
by default. The suite runs from the repository, so the store goes to a
temporary place instead: once at import, for the test modules that snapshot
the environment for a subprocess at import time, and per test through
HSSH_STORE; a test of the default location clears the variable and changes
directory itself."""

import os
import tempfile

import pytest

_SUITE_STORE_DIR = tempfile.mkdtemp(prefix="hssh-tests-")
os.environ.setdefault("HSSH_STORE", os.path.join(_SUITE_STORE_DIR, "h-ssh.db"))


@pytest.fixture(autouse=True)
def _store_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "test-h-ssh.db"))
