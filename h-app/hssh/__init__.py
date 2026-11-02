"""h-ssh: operational commands and configuration changes across fleets of network devices.

    from hssh import Fleet

Importing the package loads nothing outside the standard library; the names below load on first use.
"""

_EXPORTS = {"Fleet": "hssh.frontends.fleet", "RunReport": "hssh.model", "Target": "hssh.model",
            "Fault": "hssh.model", "FaultKind": "hssh.model"}

__all__ = list(_EXPORTS)


def __getattr__(name: str):
    if name in _EXPORTS:
        import importlib

        return getattr(importlib.import_module(_EXPORTS[name]), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
