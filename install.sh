#!/bin/sh
# h-ssh installer: one line, no package manager.
#
#   curl -fsSL https://raw.githubusercontent.com/h-network/h-ssh/develop/install.sh | sh
#
# Puts h-ssh in a Python environment of its own (~/.h-ssh/venv) and links
# `h-ssh` and `h-ssh-store` into ~/.local/bin. Running the same line again
# upgrades. Removing it:
#
#   curl -fsSL https://raw.githubusercontent.com/h-network/h-ssh/develop/install.sh | sh -s -- --uninstall
#
# takes the environment and the two links away and leaves your config,
# inventory and stores under ~/.h-ssh alone. Besides those it creates
# ~/.local/bin when missing and pip's download cache (~/.cache/pip).
#
# Needs python3 3.10 or newer with its venv module (Debian/Ubuntu: apt
# install python3-venv) and git. Knobs, all optional, given on the sh side
# of the pipe (`curl ... | H_SSH_REF=main sh`):
#   H_SSH_REF=main        the branch or tag to install (default develop)
#   H_SSH_REPO=URL        the git repository to install from
#   H_SSH_HOME=DIR        where the environment lives (default ~/.h-ssh)
#   H_SSH_BIN=DIR         where the links go (default ~/.local/bin)
#   H_SSH_PYTHON=python3.12   the interpreter to use (default: the newest found)
#
# Everything sits in main() so a download cut short does nothing at all.

main() {
    set -eu

    say() { printf '%s\n' "$*" >&2; }
    die() { say "install.sh: $*"; exit 1; }

    [ -n "${HOME:-}" ] || die "HOME is not set; set H_SSH_HOME and H_SSH_BIN instead"
    HOME=${HOME%/}
    REPO="${H_SSH_REPO:-https://github.com/h-network/h-ssh.git}"
    REF="${H_SSH_REF:-develop}"
    PREFIX="${H_SSH_HOME:-$HOME/.h-ssh}"
    BIN="${H_SSH_BIN:-$HOME/.local/bin}"
    # Absolute, so the links point somewhere whatever directory this runs from.
    case "$PREFIX" in /*) ;; *) PREFIX="$PWD/$PREFIX" ;; esac
    case "$BIN" in /*) ;; *) BIN="$PWD/$BIN" ;; esac
    PREFIX=${PREFIX%/}
    [ -n "$PREFIX" ] && [ "$PREFIX" != "/" ] || die "H_SSH_HOME must be a directory of its own"
    VENV="$PREFIX/venv"

    # Only links that point into our environment are ours to replace or remove.
    ours() { [ -L "$1" ] && case "$(readlink "$1")" in "$VENV"/*) true ;; *) false ;; esac; }

    if [ "${1:-}" = "--uninstall" ]; then
        rm -rf "$VENV"
        for tool in h-ssh h-ssh-store; do
            if ours "$BIN/$tool"; then rm -f "$BIN/$tool"
            elif [ -e "$BIN/$tool" ] || [ -L "$BIN/$tool" ]; then say "left $BIN/$tool alone: it is not ours"
            fi
        done
        say "removed $VENV and its links in $BIN; your config, inventory and stores in $PREFIX stay"
        exit 0
    fi
    [ $# -eq 0 ] || die "unknown argument '$1' (only --uninstall is taken)"

    for tool in h-ssh h-ssh-store; do
        if [ -e "$BIN/$tool" ] || [ -L "$BIN/$tool" ]; then
            ours "$BIN/$tool" || die "$BIN/$tool exists and is not ours (pipx, uv, or your own); remove it or set H_SSH_BIN"
        fi
    done

    # The newest python3 that is 3.10 or newer and can make a venv.
    usable() {
        command -v "$1" >/dev/null 2>&1 &&
        "$1" -c 'import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
    }
    PY="${H_SSH_PYTHON:-}"
    if [ -n "$PY" ]; then
        usable "$PY" || die "H_SSH_PYTHON=$PY is not a python 3.10+ with the venv module"
    else
        for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
            if usable "$candidate"; then PY="$candidate"; break; fi
        done
    fi
    if [ -z "$PY" ]; then
        case "$(uname -s 2>/dev/null)" in
            Darwin) hint="install Python 3.10+ from python.org or with  brew install python" ;;
            *) if command -v apt >/dev/null 2>&1; then hint="on Debian/Ubuntu:  sudo apt install python3-venv  (python3.12-venv for a newer python)"
               elif command -v dnf >/dev/null 2>&1; then hint="on RHEL/Fedora:  sudo dnf install python3.12"
               else hint="install Python 3.10+ with its venv module"; fi ;;
        esac
        if command -v python3 >/dev/null 2>&1; then
            version=$(python3 --version 2>&1 || echo "python3 (no version)")
            python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1 ||
                die "python 3.10 or newer is needed; found $version; $hint"
            die "$version has no venv module; $hint"
        fi
        die "python3 is needed (3.10 or newer); $hint"
    fi
    command -v git >/dev/null 2>&1 || die "git is needed to fetch h-ssh"

    mkdir -p "$PREFIX" "$BIN"
    # An environment that cannot run pip (an interrupted first run, or the
    # interpreter it pointed at was upgraded away) is made afresh.
    if [ -e "$VENV" ] && ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
        say "$VENV does not work any more; making it afresh"
        rm -rf "$VENV"
    fi
    if [ ! -x "$VENV/bin/python" ]; then
        say "creating $VENV with $("$PY" --version 2>&1) ..."
        "$PY" -m venv "$VENV"
    fi
    "$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    say "installing h-ssh ($REF) ..."
    # pip takes a same-version git requirement as already satisfied, so the
    # old copy goes first: a re-run is an upgrade whatever the version says.
    "$VENV/bin/python" -m pip uninstall --quiet --yes h-ssh >/dev/null 2>&1 || true
    "$VENV/bin/python" -m pip install --quiet --upgrade "git+$REPO@$REF" ||
        die "pip could not install h-ssh from $REPO@$REF"
    ln -sf "$VENV/bin/h-ssh" "$BIN/h-ssh"
    ln -sf "$VENV/bin/h-ssh-store" "$BIN/h-ssh-store"

    probe=$(mktemp "${TMPDIR:-/tmp}/h-ssh-install.XXXXXX")
    if ! "$BIN/h-ssh" --list-vendors >"$probe" 2>&1; then
        say "$(tail -n 3 "$probe")"
        rm -f "$probe"
        die "h-ssh is installed in $VENV but does not run"
    fi
    drivers=$(awk 'NR > 1 && $1 !~ /^broken/' "$probe" | wc -l | tr -d ' ')
    rm -f "$probe"
    say "h-ssh installed: $drivers drivers, $("$VENV/bin/python" --version 2>&1), in $VENV"
    case ":$PATH:" in
        *":$BIN:"*) ;;
        *) say "$BIN is not on your PATH; add it, e.g.:  export PATH=\"$BIN:\$PATH\"" ;;
    esac
    say "try:  h-ssh --list-vendors"
}

main "$@"
