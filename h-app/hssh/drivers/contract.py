"""What a module must offer to back a driver's `supports`.

The runner calls every driver function the same way: ``host, user, passwd``,
then the command, commands, payload or rollback number if the call has one,
then ``session_timeout, command_timeout`` (and ``commit_confirmed`` for an
edit), with ``port=`` and ``vendor_hint=`` as keywords. A capability that is
declared but not backed this way would fail on the first device, with a
``TypeError`` where a refusal should have been; ``violations()`` finds that
before any device does, and the contract test runs it over every registered
driver.

Only the declared direction is checked. A module may offer more than its
driver declares: hssh.vendors.telnet serves four dialects and has ``confirm``
and ``dry_run`` that only junos@telnet may use, until #83 splits it.
"""

import inspect

from .base import Driver

# capability -> (function name, positionals between passwd and the timeouts,
#                positionals after the timeouts, keywords it must accept)
_CALLS = {
    "show": ("show", 1, 0, ()),
    "show_batch": ("show_batch", 1, 0, ()),
    "show_structured": ("show_structured", 1, 0, ("binding",)),
    "rpc": ("rpc", 1, 0, ("fmt",)),
    "edit": ("edit", 1, 1, ()),
    "rollback": ("rollback", 1, 0, ("dry_run", "commit_confirmed")),
    "confirm": ("confirm", 0, 0, ()),
    "commit_status": ("commit_status", 0, 0, ()),
}
# policy capability -> the keywords the functions that carry it must take
_POLICIES = {
    "dry_run": {"edit": ("dry_run", "expected_diff")},
    "commit_confirmed": {"edit": ("commit_confirmed",)},
    "comment": {"edit": ("comment",), "confirm": ("comment",), "rollback": ("comment",)},
}
_ALWAYS = ("port", "vendor_hint")


def _accepts(sig: inspect.Signature, positionals: int, keywords) -> list:
    params = sig.parameters.values()
    problems = []
    if not any(p.kind is p.VAR_POSITIONAL for p in params):
        slots = sum(1 for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD))
        if slots < positionals:
            problems.append(f"takes {slots} positional arguments, the runner passes {positionals}")
    if not any(p.kind is p.VAR_KEYWORD for p in params):
        missing = [k for k in keywords if k not in sig.parameters]
        if missing:
            problems.append(f"does not accept {', '.join(missing)}")
    return problems


def violations(driver: Driver, module) -> list:
    """Every way `module` falls short of `driver.supports`; empty when it holds."""
    out = []
    if not hasattr(module, "AVAILABLE"):
        out.append("no AVAILABLE flag")
    for cap in sorted(driver.supports):
        if cap not in _CALLS:
            continue
        fn_name, middle, after, keywords = _CALLS[cap]
        fn = getattr(module, fn_name, None)
        if not callable(fn):
            out.append(f"{cap}: no {fn_name}()")
            continue
        wants = 3 + middle + 2 + after
        for p in _accepts(inspect.signature(fn), wants, _ALWAYS + keywords):
            out.append(f"{fn_name}() {p}")
        if cap == "rpc":
            batch = getattr(module, "rpc_batch", None)
            if not callable(batch):
                out.append("rpc: no rpc_batch()")
            else:
                for p in _accepts(inspect.signature(batch), wants, _ALWAYS + keywords):
                    out.append(f"rpc_batch() {p}")
    for cap, needs in _POLICIES.items():
        if cap not in driver.supports:
            continue
        for fn_name, keywords in needs.items():
            fn = getattr(module, fn_name, None)
            if fn_name != "edit" and fn_name not in driver.supports:
                continue
            if not callable(fn):
                out.append(f"{cap}: no {fn_name}()")
                continue
            for p in _accepts(inspect.signature(fn), 0, keywords):
                out.append(f"{cap}: {fn_name}() {p}")
    return out
