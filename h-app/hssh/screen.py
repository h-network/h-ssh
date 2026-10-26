"""What device text may do on the operator's terminal: nothing. A reply is
shown on a terminal with what the terminal would act on taken out (#47);
the store, the logs, a pipe and a file keep it as it came. h-ssh and
h-ssh-store both print through here."""

import re

# What a terminal would act on rather than show: C0 controls other than tab
# and newline, DEL, C1 controls, and every ESC sequence (CSI, OSC, the rest).
_TERMINAL_CONTROLS = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"   # CSI (7- or 8-bit) … final byte
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"   # OSC … BEL or ST
    r"|\x1b[@-Z\\-_]"                    # two-byte ESC sequences
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")


def terminal_safe(text: str) -> str:
    """Device output as it may be shown on the operator's terminal: a device
    (or a description field) cannot repaint, hide or retitle anything.
    Files keep the raw bytes; this is for the screen only."""
    if not text:
        return text
    return _TERMINAL_CONTROLS.sub("", text)


def is_terminal(stream) -> bool:
    """Is this a terminal? False for a closed or absent stream (`>&-` leaves
    sys.stdout as None) instead of a traceback."""
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False
