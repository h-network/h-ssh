"""#80: every driver's declared `supports` is backed by the module that does
its work, checked by signature before any device is. The contract is what the
runner relies on when it calls a function the registry said exists."""
import importlib
import types

import pytest

from hssh import drivers
from hssh.drivers import contract
from hssh.drivers.base import METHOD_CAPABILITIES


def _own(driver):
    return importlib.import_module(driver.transport.module)


@pytest.mark.parametrize("name", sorted(drivers.DRIVERS))
def test_every_registered_driver_is_backed_by_its_module(name):
    driver = drivers.get(name)
    assert contract.violations(driver, _own(driver)) == []


@pytest.mark.parametrize("name", ["junos@netconf", "none@openssh"])
def test_a_module_serving_one_driver_declares_everything_it_has(name):
    """The telnet and paramiko modules serve several dialects and offer more
    than most of them may use; a module behind one driver must not be
    under-declared, or the runner would refuse what the module can do."""
    driver = drivers.get(name)
    has = {c for c in METHOD_CAPABILITIES if callable(getattr(_own(driver), c, None))}
    assert has == driver.supports & METHOD_CAPABILITIES


def test_shared_modules_offer_what_every_dialect_on_them_declares():
    for driver in drivers.DRIVERS.values():
        if driver.transport in (drivers.TELNET, drivers.SSH):
            mod = importlib.import_module(driver.transport.module)
            for cap in driver.supports & METHOD_CAPABILITIES:
                assert callable(getattr(mod, cap, None)), f"{driver.name}: {cap}"


def test_a_declared_capability_the_module_lacks_is_a_violation():
    stub = types.SimpleNamespace(AVAILABLE=True,
                                 show=lambda host, user, passwd, cmd, st, ct, port=None, vendor_hint=None: "")
    found = contract.violations(drivers.get("junos@netconf"), stub)
    assert "rollback: no rollback()" in found
    assert "commit_status: no commit_status()" in found
    assert "rpc: no rpc()" in found
    assert not any(v.startswith("show()") for v in found)


def test_a_function_that_takes_too_little_is_a_violation():
    def show(host, user, passwd):
        return ""

    def edit(host, user, passwd, payload, st, ct, commit_confirmed=None, port=None, vendor_hint=None):
        return ""
    stub = types.SimpleNamespace(AVAILABLE=True, show=show, edit=edit, show_batch=show)
    found = contract.violations(drivers.get("junos@telnet"), stub)
    assert "show() takes 3 positional arguments, the runner passes 6" in found
    assert "show() does not accept port, vendor_hint" in found
    assert "dry_run: edit() does not accept dry_run, expected_diff" in found
    assert "confirm: no confirm()" in found


def test_a_module_without_an_available_flag_is_a_violation():
    stub = types.SimpleNamespace(show=lambda *a, **kw: "")
    assert "no AVAILABLE flag" in contract.violations(drivers.get("none@ssh"), stub)


def test_var_args_satisfy_the_contract():
    """A thin wrapper that forwards everything is a valid backing module."""
    def anything(*args, **kwargs):
        return ""
    stub = types.SimpleNamespace(AVAILABLE=True, **{c: anything for c in METHOD_CAPABILITIES},
                                 rpc_batch=anything)
    assert contract.violations(drivers.get("junos@netconf"), stub) == []
