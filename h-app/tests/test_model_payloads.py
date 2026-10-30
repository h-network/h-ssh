import pytest

from hssh.model import RunSpec


def test_payloads_default_to_an_empty_mapping():
    assert dict(RunSpec((), "edit").payloads) == {}


def test_payloads_keep_each_targets_lines_as_given():
    spec = RunSpec((), "edit", config_lines=("set a",), payloads={"R1": ("set b", "set c")})
    assert spec.payloads["R1"] == ("set b", "set c")
    assert spec.config_lines == ("set a",)


def test_payloads_are_read_only_once_the_spec_is_built():
    given = {"R1": ("set b",)}
    spec = RunSpec((), "edit", payloads=given)
    with pytest.raises(TypeError):
        spec.payloads["R2"] = ("set x",)
    given["R2"] = ("set x",)
    assert "R2" not in spec.payloads
