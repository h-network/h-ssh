# NETCONF

The `junos@netconf` driver supports `show`, `batch`, candidate edits, confirm and commit history through PyEZ. Connections use
port 830 unless the target specifies another port. The connect timeout is passed
to PyEZ, and the command timeout applies to operations on the open session.
TCP connect and the SSH banner share the connect timeout; after the banner, key exchange, login and NETCONF hello share one setup timeout.
Port 23 is rejected before any connection; NETCONF never falls back to telnet.
Show output has leading and trailing newlines removed.
A reply beginning with a Junos refusal is reported as a failed command. Plain-text
RPC diagnostics are checked across lines; ordinary command output is checked only
at the start, so later `error:` lines in logs are preserved as output.
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
keep their normal loader. New entries start on their own line and are appended under a file lock, preserving
the file's existing content, then refreshing the file cache and its resolutions.
A new process reads external changes to known-hosts files.
With `strict` or `accept-new`, revoked keys are refused even if a normal entry
matches; certificate-authority entries are skipped. Before pinning, accept-new
re-reads the file under its lock and checks any key pinned by another process.
Waiting for that lock is limited to the connect timeout and fails as a local fault.
Appending preserves existing bytes, including comments that are not UTF-8.

Library failures become `Fault` with the library's message and whether the
operation may have reached the device. The communicator does not retry.
Running out of local file descriptors is a local fault with the OS error preserved;
it does not retry or put the target into cooldown.
Closing a clean configuration session releases its candidate and lock before
disconnecting. A cleanup failure discards the transport and reports the fault;
no further cleanup RPC is sent on that session.
The background close waits up to five seconds for close-session. If closing fails,
it tears down the underlying transport so its reader thread does not linger.

## Candidate edits

Edits use PyEZ's exclusive candidate lock. Loading selects set format only when
all nonblank, noncomment lines are set-style commands; other configuration text
is preserved. Only full-line `#` comments are removed from set input. A delete's
“statement not found” warning is allowed; other load warnings and errors fail.
The Junos dialect supplies the set verbs and comment prefixes and checks the payload
before the communicator takes the lock. A refused payload is a local fault;
no configuration RPC is sent.

Diff returns the device's compare unchanged and a boolean indicating changes.
A nonempty candidate passes commit-check even for a dry run. Closing discards
uncommitted changes and unlocks only a lock this session acquired. A failed lock
never sends unlock; a dead or timed-out lock session is discarded.

Commit uses the commit timeout and supports a comment and a confirmed timer.
An unanswered commit has an unknown outcome: the transport is discarded without
rollback or replay. Verify the device before trying again. A successful commit
leaves only unlock and disconnect for cleanup.

Confirm takes the exclusive lock and rechecks commit history before sending a
plain commit. With nothing pending it returns a refusal. Commit history returns
the device's XML and `CommitStatus` from sequence zero only, including the
remaining minutes reported by the device; older confirmed entries do not count
as pending.

## Session reuse

Before each reuse, the communicator applies the current borrow's command and
commit timeouts and checks the library's connected flag. After at least 30 seconds
idle, it also sends an uptime RPC with a five-second timeout. A device refusal is
proof of a live session; a timeout or transport failure makes it unusable. The
normal command timeout is restored after the check.

Release discards an uncommitted candidate and unlocks only this session's lock,
then drops its configuration object while keeping the connection open. A known
commit rejection can be reused after successful cleanup. A failed cleanup or an
uncertain operation instead discards the transport without rollback or unlock,
interrupting any outstanding call; that session cannot be reused. Release can
use two command timeouts, separate from the five-second close-session bound.
