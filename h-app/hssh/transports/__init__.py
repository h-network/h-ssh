"""How a device is reached. The CLI engine (`cli`) types at any byte channel
according to a dialect's CliSyntax; `telnet` is one such channel. The NETCONF,
paramiko and OpenSSH transports still live under hssh.vendors until #84."""
