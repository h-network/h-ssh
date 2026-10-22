"""Exceptions that carry meaning for the retry logic."""


class NotAppliedError(RuntimeError):
    """The device cannot have acted on the request: it failed before anything
    was sent (connect/auth/lock). Safe to retry even for an edit."""


class NothingToConfirmError(RuntimeError):
    """A confirm was asked of a device with no commit-confirmed waiting: the
    timer expired (the change is already gone) or it was confirmed before.
    Nothing was sent; not retried, since the next attempt finds the same."""


class AmbiguousCommitError(RuntimeError):
    """The commit was sent but its outcome is unknown (timeout, dropped session).

    The change may or may not be on the device, so the request must never be
    retried automatically. Check the device (and any commit-confirmed timer)
    before acting again.
    """
