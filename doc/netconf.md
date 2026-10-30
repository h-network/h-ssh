# NETCONF

The `junos@netconf` driver supports `show` and `batch` through PyEZ. Connections use
port 830 unless the target specifies another port. The connect timeout is passed
to PyEZ, and the command timeout applies to operations on the open session.
Port 23 is rejected before any connection; NETCONF never falls back to telnet.
Show output has leading and trailing newlines removed.
A reply beginning with a Junos refusal is reported as a failed command.
Loading the NETCONF communicator sets ncclient's send-queue tick to 10 ms for the whole process.

For example, with a key available through SSH key discovery or the SSH agent:

```sh
h-ssh --no-store --transport netconf --vendor junos --user reviewer \
  --host-key-policy strict --target router:192.0.2.1:junos:830 -sC "show version"
```

Library callers can select a key explicitly with `Credentials.key_file`.
An explicit password or key file disables agent and default-key discovery.

The default, `off`, disables host-key verification. Opt in with `strict` to verify
the server against the library's known-hosts files, or `accept-new` to record unknown keys
in `~/.ssh/known_hosts` with an additional SSH handshake before authentication.
PyEZ then verifies the recorded key on the NETCONF connection. Known keys use
PyEZ's verification directly, and changed keys are refused. Concurrent sessions
share a process-wide known-hosts cache. Each file is parsed once, and the keys for
each host and port are resolved once and cached. Hashed names use Python's HMAC
and constant-time comparison. Each NETCONF session receives its own resolved key
mappings, retaining bare-host and port-specific verification. The cached loader
applies only while this communicator opens a PyEZ device; other ncclient sessions
keep their normal loader. New entries are appended under a file lock, preserving
the file's existing content, then refreshing the file cache and its resolutions.
A new process reads external changes to known-hosts files.

Library failures become `Fault` with the library's message and whether the
operation may have reached the device. The communicator does not retry. Closing
a configuration session attempts candidate discard, unlock and disconnect even
if an earlier cleanup step fails, then reports the first failure.
