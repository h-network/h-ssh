"""What a package outside h-ssh may hand the hssh.drivers entry point group."""
from hssh.communicators.openssh import OpenSSH
from hssh.dialects import generic
from hssh.drivers import Driver

ONE = Driver("dummy@openssh", generic.DIALECT, OpenSSH(generic.DIALECT))
DRIVERS = [ONE, Driver("other@openssh", generic.DIALECT, OpenSSH(generic.DIALECT))]
NOT_A_DRIVER = [generic.DIALECT]
NOT_EVEN_A_LIST = generic.DIALECT
TWICE = [ONE, Driver("dummy@openssh", generic.DIALECT, OpenSSH(generic.DIALECT))]
TAKEN = [Driver("fresh@openssh", generic.DIALECT, OpenSSH(generic.DIALECT)),
         Driver("junos@netconf", generic.DIALECT, OpenSSH(generic.DIALECT))]
