#!/bin/sh
# h-ssh installer: one line, no package manager.
#
#   curl -fsSL https://raw.githubusercontent.com/h-network/h-ssh/develop/install.sh | sh
#
# Puts h-ssh in a Python environment of its own (~/.h-ssh/venv) and links
# `h-ssh` and `h-ssh-store` into ~/.local/bin. Running it again upgrades;
# `sh install.sh --uninstall` removes the environment and the links and
# leaves your config, inventory and stores under ~/.h-ssh alone.
#
# Needs python3 3.10 or newer with its venv module (Debian/Ubuntu: apt
# install python3-venv) and git. Knobs, all optional:
#   H_SSH_REF=v1.0.0     the branch or tag to install (default develop)
#   H_SSH_HOME=DIR       where the environment lives (default ~/.h-ssh)
#   H_SSH_BIN=DIR        where the links go (default ~/.local/bin)
#   PYTHON=python3.12    the interpreter to use (default: the newest found)
set -eu

REPO="${H_SSH_REPO:-https://github.com/h-network/h-ssh.git}"
REF="${H_SSH_REF:-develop}"
PREFIX="${H_SSH_HOME:-$HOME/.h-ssh}"
VENV="$PREFIX/venv"
BIN="${H_SSH_BIN:-$HOME/.local/bin}"

say() { printf '%s\n' "$*" >&2; }
die() { say "install.sh: $*"; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    rm -rf "$VENV"
    rm -f "$BIN/h-ssh" "$BIN/h-ssh-store"
    say "removed $VENV and the links in $BIN; your config, inventory and stores in $PREFIX stay"
    exit 0
fi
[ $# -eq 0 ] || die "unknown argument '$1' (only --uninstall is taken)"

# The newest python3 that is 3.10 or newer and can make a venv.
usable() {
    command -v "$1" >/dev/null 2>&1 &&
    "$1" -c 'import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}
PY="${PYTHON:-}"
if [ -n "$PY" ]; then
    usable "$PY" || die "$PY is not a python 3.10+ with the venv module"
else
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if usable "$candidate"; then PY="$candidate"; break; fi
    done
fi
if [ -z "$PY" ]; then
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import venv, ensurepip' >/dev/null 2>&1 ||
            die "python3 has no venv module: on Debian/Ubuntu run  sudo apt install python3-venv  and retry"
        die "python 3.10 or newer is needed; found $(python3 --version 2>&1)"
    fi
    die "python3 is needed (3.10 or newer)"
fi
command -v git >/dev/null 2>&1 || die "git is needed to fetch h-ssh"

mkdir -p "$PREFIX" "$BIN"
if [ ! -x "$VENV/bin/python" ]; then
    say "creating $VENV with $("$PY" --version 2>&1) ..."
    "$PY" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
say "installing h-ssh ($REF) ..."
"$VENV/bin/python" -m pip install --quiet --upgrade "git+$REPO@$REF" ||
    die "pip could not install h-ssh from $REPO@$REF"
ln -sf "$VENV/bin/h-ssh" "$BIN/h-ssh"
ln -sf "$VENV/bin/h-ssh-store" "$BIN/h-ssh-store"

drivers=$("$BIN/h-ssh" --list-vendors 2>/dev/null | awk 'NR > 1 && $1 !~ /^broken/' | wc -l | tr -d ' ')
say "h-ssh installed: $drivers drivers, $("$VENV/bin/python" --version 2>&1), in $VENV"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) say "$BIN is not on your PATH; add it, e.g.:  export PATH=\"$BIN:\$PATH\"" ;;
esac
say "try:  h-ssh --list-vendors"
