# NETCONF

The `junos@netconf` driver supports `show` and `batch` through PyEZ. Connections use
port 830 unless the target specifies another port. The connect timeout is passed
to PyEZ, and the command timeout applies to operations on the open session.

For example, with a key available through SSH key discovery or the SSH agent:

```sh
h-ssh --no-store --transport netconf --vendor junos --user reviewer \
  --host-key-policy strict --target router:10.91.0.2:junos:830 -sC "show version"
```

Library callers can select a key explicitly with `Credentials.key_file`.
An explicit password or key file disables agent and default-key discovery.

`strict` verifies the server against the library's known-hosts files. `off`
disables host-key verification. The default, `accept-new`, records unknown keys
in `~/.ssh/known_hosts` with an additional SSH handshake before authentication.
PyEZ then verifies the recorded key on the NETCONF connection. Known keys use
PyEZ's verification directly, and changed keys are refused. Concurrent sessions
within one process serialize their known-hosts reads and writes.

Library failures become `Fault` with the library's message and whether the
operation may have reached the device. The communicator does not retry. Closing
a configuration session attempts candidate discard, unlock and disconnect even
if an earlier cleanup step fails, then reports the first failure.

Structured output and configuration operations remain unimplemented and are not
advertised as driver capabilities.
