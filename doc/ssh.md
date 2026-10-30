# Paramiko SSH

The SSH communicator connects directly to the target host. An explicit target port
wins; otherwise SSH uses port 22. It does not read SSH client configuration.
The Junos read slice supports `show` and `batch`, through the shared CLI engine.
Driver registration follows the fleet acceptance pass; edits are a later slice.

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
banner, one `setup` deadline covers key exchange, authentication, channel open,
PTY and shell acknowledgements, prompt discovery and paging setup. Expiry closes
the connection to wake blocked requests. Failed or interrupted setup closes the
client. Error reports retain the phase and underlying exception; receiving the
SSH banner distinguishes a reached device from a pre-banner failure.

The shell uses a vt100 PTY, 511 columns by 1000 rows. The shared engine owns echo,
prompt, paging and reply handling. Every channel write observes one absolute
deadline across partial writes and rekey waits. A disconnected channel raises
`ConnectionError`, and a deadline failure raises `TimeoutError`.

Pooling reuses only an authenticated, live transport with a synchronized engine.
The engine receives the current operation timeouts on reuse. At 30 seconds idle,
an empty-line prompt probe has a five-second deadline. Release preserves a healthy
session; discard closes the connection without sending CLI cleanup commands.
