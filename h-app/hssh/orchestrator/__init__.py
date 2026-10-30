"""The orchestrator: executes a RunSpec through drivers and owns all policy and defaults (section 3.2). The defaults import light; the runtime (scheduler, drivers, communicators) loads on the first use of execute, run or the session manager."""

from hssh.orchestrator.defaults import (DEFAULT_CONFIRMED_MINUTES, DEFAULT_EDIT, DEFAULT_HOST_KEY_POLICY,
                                        DEFAULT_POLICY, DEFAULT_PROBE, DEFAULT_SAFETY, DEFAULT_SKIP_UNREACHABLE,
                                        DEFAULT_STORE, DEFAULT_TIMEOUTS, DEFAULT_TRANSPORT, DEFAULT_VENDOR,
                                        DEFAULT_WORKERS, check_comment, check_confirmed_minutes, complete,
                                        default_credentials, default_username)

_RUNTIME = {"execute": "hssh.orchestrator.scheduler", "run": "hssh.orchestrator.scheduler",
            "SessionManager": "hssh.orchestrator.sessions", "CLOSE_WAIT": "hssh.orchestrator.sessions"}

__all__ = ["DEFAULT_CONFIRMED_MINUTES", "DEFAULT_EDIT", "DEFAULT_HOST_KEY_POLICY", "DEFAULT_POLICY", "DEFAULT_PROBE",
           "DEFAULT_SAFETY", "DEFAULT_SKIP_UNREACHABLE", "DEFAULT_STORE", "DEFAULT_TIMEOUTS", "DEFAULT_TRANSPORT",
           "DEFAULT_VENDOR", "DEFAULT_WORKERS", "check_comment", "check_confirmed_minutes", "complete", "default_credentials",
           "default_username", "execute", "run", "SessionManager", "CLOSE_WAIT"]


def __getattr__(name: str):
    if name in _RUNTIME:
        import importlib

        return getattr(importlib.import_module(_RUNTIME[name]), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
