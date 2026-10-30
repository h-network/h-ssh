import pytest

from hssh.dialects import eos, generic, ios, junos, nxos


@pytest.fixture(params=[generic.DIALECT, junos.DIALECT, ios.DIALECT, nxos.DIALECT, eos.DIALECT],
                ids=['generic', 'junos', 'ios', 'nxos', 'eos'])
def dialect(request):
    return request.param


@pytest.fixture(params=[ios.DIALECT, nxos.DIALECT, eos.DIALECT], ids=['ios', 'nxos', 'eos'])
def ios_dialect(request):
    return request.param


@pytest.fixture(params=[generic.DIALECT, junos.DIALECT], ids=['generic', 'junos'])
def redacting_dialect(request):
    return request.param
