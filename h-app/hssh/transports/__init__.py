"""How a device is reached: `netconf` (PyEZ), `ssh` (paramiko), `openssh`
(the ssh binary) and `telnet` (a raw socket). Each module does one
transport's work for every dialect on it, told the dialect by the
vendor_hint it is called with. The CLI engine (`cli`) types at any byte
channel according to a dialect's CliSyntax; the paramiko shell, the
`ssh -tt` process and the telnet socket are such channels."""
