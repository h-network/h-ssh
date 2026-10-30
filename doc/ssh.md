# Paramiko SSH

The SSH communicator connects directly to the target host. An explicit target port
wins; otherwise SSH uses port 22. It does not read SSH client configuration.
Junos supports `show`, `batch`, `edit`, `confirm` and `commit_status`.
Show and batch commands use SSH exec channels on the authenticated connection,
ending at EOF and exit status. A batch
keeps the connection across commands. Reads do not allocate a PTY, learn prompts,
disable paging or wait for a quiet prompt.

Edits, confirmations and commit history use one lazily opened interactive shell.
The shared engine acquires the exclusive candidate before loading, stops at the
first refused line, and returns a diff whose `data` says whether anything changed.
The orchestrator chooses dry run or apply and does not commit an empty diff.
Commit uses the supplied comment and optional confirmed timer. Confirmation is a
separate run; the engine checks the newest pending commit again while holding the
exclusive lock before sending the confirming commit. Commit history returns the
newest entry as `CommitStatus`.

Each loaded line uses the configured command budget. Commit uses the configured
commit budget. A write or reply lost after a commit may have been sent is
`OUTCOME_UNKNOWN`; subsequent cleanup sends no discard command. The engine
cleans only the uncommitted candidate it acquired.

A supplied password disables implicit SSH agent and key-file discovery. An
explicit key file is expanded from `~` and passed to Paramiko; it also disables
implicit discovery. When neither is supplied, Paramiko uses the agent and its
usual key-file discovery. Authentication happens in SSH. Credentials are never
sent to the interactive CLI.

Host-key policy comes from the run settings; the orchestrator defaults it to
`off`. Under `off`, the communicator does not read or write known hosts, including
revocation entries. `strict` rejects unknown or changed keys. `accept-new` saves
only an unknown host and refuses a changed key before authentication. Both use
only `~/.ssh/known_hosts`, with bracketed host-and-port names for nonstandard ports.
Plain and hashed entries are supported. `@revoked` keys are rejected; CA entries
and unsupported ordinary entries are ignored. Malformed revocation entries are
reported as local errors rather than silently ignored.

Parallel accept-new writers lock `known_hosts`, re-read and verify the key, then
append. Existing contents and permissions remain intact, and a missing final
newline is supplied. Lock acquisition uses the remaining setup deadline. Cached
reads are invalidated when the file identity, size or modification time changes.

TCP connection and receipt of the SSH banner share `connect` seconds. After the
banner, one `setup` deadline covers key exchange and authentication. Each exec
read has its own `command` deadline covering channel open, request acknowledgement,
output and exit status. A nonzero exit status or a refusal at the start of the
reply is reported as `REFUSED`, even when the server exits successfully. A dropped
connection before output ends is `SESSION_LOST`; incomplete output is not returned
as success. Expiry closes the connection to wake blocked requests. Failed or
interrupted setup closes the client. Error reports retain the phase and underlying
exception; receiving the SSH banner distinguishes a reached device from a
pre-banner failure.

An interactive operation initializes the shell only when it first needs one,
using the remaining setup deadline. It uses a vt100 PTY, 511 columns by 1000 rows,
and the shared engine for echo, prompt, paging and reply handling. Every shell
write observes one absolute deadline across partial writes and rekey waits. A
disconnected channel raises `ConnectionError`; expiry raises `TimeoutError`.
Shell setup failures are reported as `TIMEOUT` or `SESSION_LOST` with the failing
phase; failed or interrupted setup tears down the connection. The orchestrator's
first load or commit-history allowance includes setup, while the communicator
keeps the original absolute setup deadline.

Pooling reuses only an authenticated, live transport whose last operation left it
usable. Current timeouts apply on reuse. At 30 seconds idle, an exec-only session
checks liveness by opening and closing a session channel within five seconds. An
existing interactive engine uses its synchronized-prompt probe instead. A later
borrow that first needs a shell gets its current setup allowance. Release preserves
a healthy session after the engine discards its uncommitted candidate and exits
configuration mode. Graceful close allows two command budgets for discard and
exit before closing the client. Discard tears down only the transport, without
invoking engine cleanup or sending CLI commands.
