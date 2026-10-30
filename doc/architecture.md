# h-ssh Architecture

## 1. Purpose

h-ssh is a command-line tool and Python library for running operational commands and configuration
changes across fleets of network devices. It reaches devices over SSH, NETCONF and telnet. It records
every result in a local SQLite store, and every change in an audit log.

### Goals

- **Central orchestration.** All decision logic lives in one orchestrator. That covers scheduling,
  retries, safety policy, the edit and commit lifecycle, cancellation and recording.
- **Pluggable communicators.** Each way of reaching a device is a module behind one interface. A
  communicator executes and reports. It does not decide.
- **Pluggable vendors.** Vendor behaviour is described by dialects, separately from transports. New
  vendors and transports can be added from outside the package.
- **Safe changes.** Dry-run by default, commit-confirmed support, and a per-device safety gate.
- **Durable records.** Every run and result is stored. Every change is audited.
- **Verified on real devices.** Behaviour is validated against a fleet of virtual network devices.

### Non-goals

- A configuration management or templating system.
- An inventory source of truth.
- A long-running service or daemon.

## 2. System overview

```
┌──────────────────────────── Front ends ────────────────────────────┐
│  CLI   ·   Fleet library API   ·   run files   ·   profiles        │
└───────────────────────────────┬────────────────────────────────────┘
                                │  RunSpec
┌───────────────────────────────▼────────────────────────────────────┐
│                           Orchestrator                             │
│  Scheduler · Policy (retry, safety gate) · Edit lifecycle ·        │
│  Session manager · Probe · Cancellation · Recorder                 │
└──────┬───────────────────────────────┬─────────────────────┬───────┘
       │ Driver = dialect@transport    │ records             │ records
┌──────▼──────────────────────┐ ┌──────▼──────┐       ┌──────▼──────┐
│ Driver registry             │ │ Result store│       │ Audit log   │
│  Communicators   Dialects   │ │ (SQLite)    │       │ (JSONL)     │
│  ssh (paramiko)  junos      │ └─────────────┘       └─────────────┘
│  openssh (ssh)   ios        │
│  netconf (PyEZ)  nxos, eos  │
│  telnet          generic    │
└──────┬──────────────────────┘
       │ Result | Fault
       ▼
    Devices
```

Requests flow down. Each front end turns user input into a `RunSpec`. The orchestrator executes the
`RunSpec` through drivers. Communicators return a `Result` or raise a `Fault`. The orchestrator decides
what happens next and records the outcome.

## 3. Components

### 3.1 Front ends

The CLI, the Fleet library API, run files and profiles are front ends. Each one:

- parses its input
- resolves configuration precedence: flags, then run file, then profile, then `~/.h-ssh/config`, then
  the orchestrator's defaults; four settings have an environment step between the run file and the
  config: the user (`HSSH_USER`, then the login name) and the three paths `HSSH_STORE`, `HSSH_AUDIT_LOG`,
  `HSSH_SAFETY_FILE`, resolved in `frontends/settings.py` for the CLI and `h-ssh-store` alike, so both
  find the same store; an explicitly empty path is refused, not taken for the flag left out
- builds a `RunSpec`
- passes the `RunSpec` to the orchestrator and renders the `RunReport` it returns

Front ends make no decisions about devices. A behaviour available in the CLI is available in the library
through the same `RunSpec`.

`--every SECONDS` (1 to 86400) is a front-end loop: one run per tick with the same `RunSpec`, every tick
kept in the store, and each tick's rows compared with the last kept run's through the store's reader
(`Store.results(run_id=…)`), so `h-ssh-store` can go back to any two ticks. It prints one line per tick
(`tick N HH:MM:SS: a OK, b failed[, c skipped], d changed; run ID`) and, per device whose reply, outcome or
fault changed, a header (`--- NAME: command`, `OK -> FAIL (reason)` or `new`) and a unified diff of the output.
A store the reader cannot open ends the watch (exit 2); Ctrl-C between ticks says how many ticks were kept and
exits 130. A watch is reads only, needs the store (`--no-store` is refused) and prints neither `--json` nor
`--raw`; `--times N` stops after N ticks and goes only with `--every`.

Before anything runs the CLI refuses the flags that would do nothing or contradict each other, in one line and
exit 2: a second mode, `-y`/`--comment`/`--commit-confirmed` without an edit, `--format` without `-sC`,
`--no-store` with `--store`, `--raw` with `--json` or `-v`, a `--save-output` path that exists and is not a
directory, and a parser error is the message alone, not the usage block. Input is plain text: a `-sC` or batch
command is one line (a line break would run two commands), and the username, from whichever source, carries no
control character; both are checked before the password. Every target name, typed or from an inventory, is a
safe file name (`hssh.paths.validate_device_name`), in the CLI and the library alike, since the name becomes
a saved-output and set-file name.

The CLI refuses before the password is asked what the run could not go on with: a commit comment or timer the
orchestrator's `check_comment` and `check_confirmed_minutes` reject, and a run file that applies changes
without `commit_confirmed` (nobody watches a pipeline). An edit payload (`-eC` text, one `-eB` file for every
target, or `-eD DIR` with one `<NAME>.set` per target, read before the password) loses its blank lines and the
lines that start with each target's own dialect comment prefixes; an inline `#` is sent as written; a payload with
a control character, or with nothing left after the comments, is refused naming the file and the line. With `-eD`
a target without its file ends the run before anything is sent, unless `--allow-missing`, which skips those
targets and says so; a set file name is the device name, checked to stay inside the directory. `--every` repeats
reads only, never an edit. After an apply with
a timer the CLI prints the minutes left per device and the command that confirms them, rebuilt from the run's
own arguments. Exit codes: 0; 1 a device failed; 2 refused before anything was sent; 3 nothing failed but not
everything ran; 4 a record was not kept; 130 interrupted. A `--every` watch exits with the worst of its runs,
in that order: 130, 4, 2, 1, 3, 0. One `[h-ssh] {…}` JSON summary line goes to stderr per run. The verdict
line (`run ID: a ok, b failed, c skipped (n reason, …); k record(s) not kept`) names what was skipped by
reason, so a run the gate or the probe kept from every device never reads as all OK; under `--raw` stdout is
device output only and the verdict goes to stderr when something failed, was skipped or was not kept, as does
`Interrupted. Completed a of n device(s).` Device text shown on a terminal goes through `hssh.screen.terminal_safe`
(control sequences stripped); a pipe, a file and the store get it as it came. A reader that leaves (`| head`)
ends the program quietly with exit 0: the record is the store, the screen is best effort. `--json`
renders each `Result.data` through the store's `json_data`, so the file and the store hold the same shapes.
The run's provenance in `RecordSettings` is the front end's: `origin` is `h-ssh` from the CLI and `fleet` from
the library (unless the caller set one), `version` is the installed package version from `importlib.metadata`,
None when h-ssh runs from source. Set-file names and containment (`-eD`) use the shared `hssh.paths` helpers.

The Fleet keeps its sessions. It owns a pooled `SessionManager` for its lifetime and hands it to every
`run(spec, sessions=…)`, so a device is logged in once per Fleet: `show()`, `batch()` and
`edit()` on the same Fleet reuse the session the first call opened (a changed credential or policy opens anew,
section 3.2). One run at a time: a call while another is in flight raises `RuntimeError`, and so does a call on a
closed Fleet. `close(wait=0)` closes the kept sessions, giving the devices `wait` seconds in all to acknowledge,
and `with Fleet(...) as fleet:` does it on the way out; a Fleet dropped without `close()` closes its sessions
when it is collected or at interpreter exit (`weakref.finalize`), so no session outlives the script. The CLI
stays one session per run: its `run()` owns a manager without pooling and closes it when the run ends.

### 3.2 Orchestrator

The orchestrator executes a `RunSpec` and owns all policy. It defines the default of every `RunSpec`
setting: the front ends and the model take them from it, and define none of their own. A transport's
default port is held by its protocol, and a target's own port overrides it.

| Part | Responsibility |
|---|---|
| Scheduler | Expands targets, runs them in parallel up to the worker limit, and keeps the order of results stable |
| Policy | Maps each `Fault` to an action: retry, fail, skip, or cool down. Applies the safety gate |
| Edit lifecycle | Runs the edit state machine (section 5.3), including dry-run, commit-confirmed and confirm |
| Session manager | Opens, reuses and closes sessions. A close runs beside the work, so it never holds a worker, and the run waits for every close before it ends. Pooling across calls is a session-manager option, not a communicator feature: a caller (the Fleet API) hands `run` or `execute` its own manager and keeps it, across event loops, and closes it with `close_all(timeout)`, which still joins the closes when the interpreter is shutting down; the CLI's run owns and closes its own. `run` refuses to start inside a running event loop and names `execute` instead. A session is keyed by driver, host, the port the connection uses, user, host-key policy and the credential as a process-secret HMAC, so a changed secret or policy opens anew. One session per key: a second borrower waits for it instead of logging in again. A kept session is offered again only after the communicator's `reuse` vouches for it (the cheap check on every borrow, the device asked past its idle threshold) under a 5 s budget; a borrow owns it through its `release` cleanup (two command timeouts), and only then is it idle. A session in doubt (timeout, loss, unknown commit outcome, a cancelled or over-budget call still running, a failed cleanup or close) is torn down by `discard` with no cleanup and never offered again. The kept sessions live inside the open-file budget (6 descriptors per worker, 4 per kept session, 1 per probe, 32 base): when a session goes idle and before every open or probe, the least recently used idle sessions are closed while the limit cannot hold the kept ones beside what is about to run, a close still running counted as held until its thread ends; before an open or the probe the manager waits for those closes (1 s in all) so the descriptors are really free, and the probe runs no more at once than the budget still has. Workers are lowered to the limit per run and said once per session manager, so a Fleet hears it once, not on every call; a lowered probe concurrency is said the same way |
| Probe | Pre-flight reachability check per target, on by default and turned off per run. It checks the address and port the connection will use, asked the way each transport's library reads the ssh client's configuration (`Communicator.ssh_config`): NETCONF as PyEZ and ncclient read `~/.ssh/config` (HostName, Port, ProxyCommand), the OpenSSH transport as `ssh -G` prints it for the run's user (HostName, Port, ProxyJump, ProxyCommand; eight at once, on threads, under the connect timeout), paramiko SSH and telnet the target's host and port directly. A target reached through a proxy is not probed; one whose route `ssh -G` cannot tell is that target's `LOCAL` failure before any login. Its outcome is expressed as the same fault kinds |
| Cancellation | Handles interruption (section 5.4) |
| Recorder | Writes every result to the store and every change to the audit log, with redaction |

### 3.3 Driver registry

A driver is a pair: a dialect and a communicator, named `dialect@transport`, for example `junos@netconf`
or `ios@ssh`. The registry:

- holds the built-in drivers
- loads third-party drivers from the `hssh.drivers` entry point group, each entry point taken whole or not at all
- maps each target's vendor and transport to a driver
- refuses a mode the driver's capabilities don't include, before anything is sent

### 3.4 Communicators

A communicator implements the interface in section 4.1 for one transport.

| Communicator | Library | Typical use |
|---|---|---|
| `netconf` | PyEZ / ncclient | Junos |
| `ssh` | paramiko | any SSH device, CLI-driven |
| `openssh` | the system `ssh` binary | hosts where paramiko cannot be installed, or where ssh config is needed |
| `telnet` | socket with option negotiation | console servers and legacy devices |

A communicator:

- opens and closes sessions, using its library's own connection, timeout and host-key handling. Closing a
  session discards any uncommitted changes, in the communicator's own way
- executes one operation per call
- converts library errors into a `Fault` of the right kind, keeping the library's message as detail
- reports whether anything reached the device before a failure

A communicator does not retry, apply policy, write records, or keep state outside its session.

CLI-driven communicators (`ssh`, `openssh`, `telnet`) share one **CLI engine**. The engine drives an
interactive channel: login, prompt detection, paging, command execution and line-by-line configuration.
The channel's `send(data, deadline)` and the engine's `login(deadline)` take absolute `time.monotonic()`
deadlines; each adapter holds one deadline across the whole write. Login takes no credentials: SSH and
OpenSSH sessions arrive authenticated.
It reads vendor behaviour from the dialect.

For CLI reads, login learns a whole-line prompt and disables paging within the remaining setup deadline.
Junos uses `set cli screen-length 0`; the echoed command also separates any delayed banner from replies.
Each command's write, reply and prompt settling share one command deadline. The reader decodes UTF-8
incrementally, handles terminal redraws and recognises pager markers only on the current terminal line.
It removes command echoes, prompt context and terminal control sequences, without redacting or formatting
the reply. A refusal at the start of a reply is `REFUSED`; an error-looking line later in output stays output.
Commands containing controls, Tab or invalid Unicode are refused before typing; Junos's encoder quotes
literal `?` for the line editor.

A timeout or disconnect makes the engine unready, so that session is discarded and a later batch command
uses a fresh login. Pooling asks the transport's cheap liveness check first; an idle probe sends one empty
line and waits for the learned prompt under its absolute deadline. Releasing a read session requires it
to remain synchronized.

Candidate edits acquire exclusive configuration before loading any line. The whole payload is validated
first; full-line comments and blank lines are skipped. Each line has one command deadline, and a refused
line stops the load immediately with its line number and device complaint. Accepted warnings remain in
the load result. A diff returns `data=bool changed`; prompt context and blank output never make an empty
diff into a change. The orchestrator decides whether to commit.

Commit uses the dialect's `build_commit` and one commit deadline. The engine marks it as sent before the
write: a partial write or lost reply is `OUTCOME_UNKNOWN`, and no later cleanup sends rollback or exit.
An explicit device refusal is `COMMIT_FAILED`, leaving the owned candidate available for cleanup.
Release rolls back only an acquired, uncommitted candidate, then exits configuration; the synchronized
shell remains reusable. Close performs the same cleanup before ending the channel. Discard only closes
the channel and never sends CLI commands. A timeout or disconnect also prevents graceful cleanup.

Confirm acquires exclusive configuration and rechecks the newest commit before its one plain commit;
no pending timer is `REFUSED`. Junos history parses only sequence zero, including the device's `5mins`
timer format, and ignores timers on older entries. Junos commit comments reject controls, Tab and double
quotes, quote backslashes, and retain the 512 UTF-8 byte limit; literal `?` uses the line-editor encoder.

### 3.5 Dialects

A dialect describes one vendor's CLI behaviour as data and small parsing hooks:

- the prompt pattern, the anchored prompt name and tail the engine learns the device's own prompt from, and the
  context lines the CLI prints with its prompt
- paging control: the command that turns the pager off, the pager marker as a whole line, and the reply to it
- the refusal and warning patterns
- how to enter and leave configuration mode, how to commit (`build_commit`), diff and read the commit history
  (`parse_commit_history`), and how to discard uncommitted changes, if the vendor has a candidate model
- `config_history_command`: the history command while configuration is held, or `None` when unsupported;
  Junos uses `run show system commit`, alongside operational `history_command` (`show system commit`)
- how a validated line is typed (`encode_line`: bytes, newline included; Junos escapes a literal `?`)
- the read-command rule, deciding which commands are safe to retry
- a shortcut library of named commands

Dialects contain no I/O and no policy.

`comment_prefixes` identifies full-line comments after leading whitespace: `#` for Junos and generic,
and `#` or `!` for IOS, NX-OS and EOS. Inline `#` remains part of the command.
`check_edit(lines)` returns refusal text, or `None`, without changing the supplied lines. Every dialect
refuses an empty or comment-only payload. Junos additionally requires lowercase set-style verbs:
`set`, `delete`, `activate`, `deactivate`, `insert`, `rename`, `copy`, `annotate`, `protect`, `unprotect`.
It refuses commit commands (including `commit;` and unique abbreviations starting at `com`), control
characters and Tab in non-comment lines, and reports the original line number. Commit and confirm
are separate operations, never configuration payloads.

Junos and generic `redaction_patterns` identify credential text and secret XML/JSON names for the audit
writer. Junos also recognises `## SECRET-DATA` and trap-group communities. Quoted values include escaped
quotes; a key identifier alone does not consume the following line. The writer replaces whole matches.
For valid JSON text, the writer parses first and detects secret keys by searching these patterns against
`json.dumps(key) + ': "x"'` (without braces). A matching key's entire value is masked, including objects
and lists. IOS, NX-OS and EOS redaction patterns wait for the CLI transport phase.

### 3.6 Result store

One SQLite database, `./h-ssh.db` by default. The recorder writes. `h-ssh-store` reads: it lists
runs, shows output, compares results and exports. The schema is in section 6.

The recorder proves every record destination before the probe: the audit log and the run log by a no-content
append, the saved-output directory by a private temporary file. The store is opened and created by the run row,
written after the probe and before the first target. A failure in either refuses the run as `LOCAL` before any
device is contacted. Once targets run, every record is attempted on its own: each store row, each audit entry,
the saved-output file, the log line, the run row's finish and the store's close. One that cannot be written is
counted once in `RunReport.not_kept`; each destination's failure is said once on stderr, with its first error; the device outcome stands, no cooldown follows, and the
report still reaches the caller, so a store that vanished mid-run ends in exit 4, not a traceback. Every operation row carries the target's final
status. Saved output is named through `hssh.paths` inside its directory.

### 3.7 Audit log

An append-only JSONL file. One entry per action that changed or could change a device, including dry
runs. The format is in section 6.

## 4. Interfaces

### 4.1 Communicator interface

```python
class Communicator(Protocol):
    capabilities: frozenset[str]          # e.g. {"show", "batch", "edit", "commit_confirmed"}
    default_port: int                     # e.g. 830 for netconf
    banner: bytes | None                  # what the port sends first, for the probe; None: a connect is enough
    ssh_config: Literal["paramiko", "openssh"] | None   # whose ssh client config the transport reads, so the probe asks where the connection really goes: "paramiko" (~/.ssh/config: HostName, Port, ProxyCommand), "openssh" (as `ssh -G` prints it, ProxyJump too), None (reads none)

    def open(self, target: Target, creds: Credentials, timeouts: Timeouts,
             host_key_policy: HostKeyPolicy) -> Session: ...
    def close(self, session: Session) -> None: ...
    def reuse(self, session: Session, timeouts: Timeouts, idle_seconds: int) -> bool: ...  # before a borrow: apply the timeouts; cheap check always, the device asked only past idle_seconds
    def release(self, session: Session) -> None: ...   # end of a borrow: discard the candidate, unlock; raises Fault when that fails
    def discard(self, session: Session) -> None: ...   # session in doubt: tear down, no rollback or unlock, interrupt a running call, never raises

    def show(self, session: Session, command: str) -> Result: ...
    def structured(self, session: Session, rpc: str, fmt: str) -> Result: ...   # NETCONF only

    def load(self, session: Session, lines: list[str]) -> Result: ...           # candidate or line-by-line
    def diff(self, session: Session) -> Result: ...                           # data: bool, whether anything changed
    def commit(self, session: Session, confirmed_minutes: int | None, comment: str | None) -> Result: ...
    def confirm(self, session: Session) -> Result: ...
    def commit_history(self, session: Session) -> Result: ...                 # data: CommitStatus
```

Batch execution is the orchestrator calling `show` repeatedly on one session.
A refused or timed-out command does not stop the batch; a lost session does.

### 4.2 Result

```python
@dataclass(frozen=True)
class Result:
    output: str                  # device output as received
    data: ResultData = None      # None, bool, dict, list or a dataclass: what the store keeps as JSON

@dataclass(frozen=True)
class CommitStatus:              # commit_history's data, from the newest history entry
    pending: bool
    remaining_minutes: int | None
    newest: str
```

### 4.3 Fault

```python
class FaultKind(Enum):
    UNREACHABLE      # the connect was refused or cannot be attempted: nothing listening, no route, no such name
    AUTH             # credentials rejected
    HOST_KEY         # host key rejected by the communicator's library
    TIMEOUT          # nothing answered in time: at open, no TCP answer or no SSH banner within the connect timeout (reached_device false), or the banner came and setup did not finish within the setup budget (true); in session, no reply
    SESSION_LOST     # the session closed unexpectedly
    REFUSED          # the device rejected the command or configuration
    COMMIT_FAILED    # the commit was rejected; nothing was committed
    OUTCOME_UNKNOWN  # a commit was sent and no reply arrived
    UNSUPPORTED      # the driver does not support the operation
    LOCAL            # a local error: file, resource, configuration

@dataclass(frozen=True)
class Fault(Exception):
    kind: FaultKind
    detail: str              # the library's or device's own message
    reached_device: bool     # whether any part of the operation reached the device
```

`reached_device` is what makes retries safe. The orchestrator never retries an operation that reached the
device, unless the dialect marks it as a read.

### 4.4 Default policy

| Fault | Read | Edit, nothing reached the device | Edit, reached the device |
|---|---|---|---|
| `UNREACHABLE` before login | fail | fail | n/a |
| `TIMEOUT` before login, no TCP answer or no SSH banner (`reached_device` false) | retry after 0.5 s, then 1 s, then fail | retry after 0.5 s, then 1 s, then fail | n/a |
| `SESSION_LOST` before login, the device dropped the connection during setup | retry after the retry pause (2 s), then fail | retry after the retry pause (2 s), then fail | n/a |
| `TIMEOUT` before login, the banner came but setup did not finish in the setup budget (`reached_device` true) | fail | fail | n/a |
| `AUTH`, `HOST_KEY` | fail | fail | n/a |
| `TIMEOUT`, `SESSION_LOST` in session | retry | fail | fail, cool down |
| `REFUSED`, `COMMIT_FAILED` | fail | fail | fail, cool down |
| `OUTCOME_UNKNOWN` | n/a | n/a | fail, cool down, never retried or rolled back, the session discarded, flagged for manual check |
| `UNSUPPORTED`, `LOCAL` | fail | fail | fail |

The retry count, pauses and cooldown period are policy settings, not communicator settings. A cooldown is only
for what the device did: no fault with `reached_device` false cools a device down.

## 5. Execution model

### 5.1 RunSpec

A `RunSpec` holds: the targets, the mode (`show`, `batch`, `structured`, `edit`, `confirm`,
`commit_status`), the commands or configuration lines, the per-target payloads (a target name to its own
lines; a target not named gets the configuration lines, and when payloads are given a target in neither has no
payload and is skipped), credentials, timeouts (`connect` for the TCP connect and the
SSH banner, `setup` as one deadline from the banner across key exchange, login and the NETCONF hello, `command` per
operation, `commit`),
the worker limit, the safety
settings, and the recording settings (the record paths, and the run row's provenance: `argv`, `origin` and
`version`, supplied by the front end, all optional).

### 5.2 Concurrency

The orchestrator runs on asyncio. Blocking libraries such as paramiko and PyEZ run on daemon worker threads, at most
the worker limit at once, so a call that never returns keeps its thread, never the interpreter's exit. Each communicator
call gets its own timeout (`connect` plus `setup` for open, `command`, or `commit`) plus a grace period; one that has not
returned by then is that target's `TIMEOUT` fault, and its thread is left to finish. Each target is one task. A target's operations run in order on one session. Targets
run independently, and one target's failure does not affect another's. A `TIMEOUT` on one command of a batch ends the
use of that session before the next command: it is torn down at once, and the rest of the batch goes on under the read
policy on a fresh session, one more login; a `REFUSED` reply continues on the same session and `SESSION_LOST` still ends
the batch. Every open that is not a borrow's first (that fresh session, or an open after a kept session fails its reuse
check) is counted by the safety gate's `count_login` first: a full window refuses it as a `LOCAL` fault, "safety gate: …",
which skips the target at the start of a borrow and fails it mid-batch. The session manager's reuse check runs under a 5 s budget and its release cleanup under two command timeouts. A candidate loaded in one `load` call has a command timeout per line and one for the lock, since a CLI types it line by line, and the setup timeout on top, as has the first `load` line without a candidate and `commit_history`: a target's first operation may start the transport's shell inside the setup deadline the communicator keeps; `diff` has two, `commit` the commit timeout. A CLI transport's timed-out command ends its session the same way: no resynchronisation, the late reply dies with the session.

### 5.3 Edit lifecycle

```
OPEN → LOAD → DIFF ──(dry run)──────────────────────────────► CLOSE
                 └─(apply)→ COMMIT ─(confirmed N)→ PENDING ─► CLOSE
                                                     │
                                              later run: CONFIRM
```

- **Dry run** is the default: load, diff, close. Closing discards the candidate, so nothing is committed.
- The probe runs before `OPEN`. An edit whose probe found a target dead stops before any device, with one audit
  entry per dead target and no run row, unless `skip_unreachable` is set, which skips those targets; a read fails them.
- **Apply** requires `-y`. Without it, an edit is a dry run. A diff whose data is False sends no commit: an empty
  commit could confirm someone else's pending commit-confirmed.
- The target is marked past `COMMIT` before the commit is sent, so an interrupt waits for the reply.
- A target's payload is its entry in the per-target payloads, else the configuration lines. When payloads are given
  and a target has neither, it is skipped before `OPEN`, recorded as `open` `LOCAL` "no configuration for this target".
- Before `OPEN`, the payload goes through the driver dialect's `check_edit`; a refusal fails the target as `LOCAL`
  with the dialect's text, so the rule holds for every caller, not only the CLI.
- **Commit-confirmed** leaves a pending commit. The report lists the devices with a pending commit and the
  minutes left on each, from the device; the front end builds the command that confirms them. A confirm run reads the
  commit history first and sends the confirm only when its `CommitStatus` is pending; otherwise it is `REFUSED`.
- The orchestrator checks the timer and comment before anything is sent, through `check_confirmed_minutes` (1 to
  65535) and `check_comment` (one non-empty line, at most 512 UTF-8 bytes, no control characters); front
  ends call the same helpers before asking for a password.
- On a fault after `LOAD` and before `COMMIT`, the orchestrator closes the session, which discards the
  uncommitted changes. Where the dialect has no candidate, it stops and reports which lines were applied.
- The safety gate is consulted before `OPEN` for edits. Cooldowns persist across runs in the safety file. Before the
  run starts, the policy counts the logins the run may make to one device (retries + 1 per listing) against the rate
  limit and refuses the run when it would pass it, so the gate never turns a device away half-way.
- The gate keys a device by host and the port the connection uses: the orchestrator fills a target's port from the
  transport's default before every gate call, so the gate holds no default-port table. A target the gate holds is
  not probed and is skipped before `OPEN` with the reason, as is one the gate turns away at login, so a held fleet
  ends with skipped targets (exit 3), not failures. Gate state that cannot be used (an unreadable or corrupt safety
  file) refuses the run before the probe; found at a target's login it is that target's `LOCAL` failure; a cooldown
  or release that cannot be persisted is said once and the verdict stands. A local refusal or a recording failure
  never cools a device down.

### 5.4 Cancellation

1. On the first interrupt, the scheduler starts no new targets. Targets that have not started are recorded
   as skipped. An interrupt during the probe cancels it: a read is still recorded as a run, every target skipped
   "interrupted during the probe"; an edit stopped there is refused as `LOCAL` and leaves no run row.
2. Targets past `COMMIT` are waited for and recorded. Other in-flight targets are cancelled and recorded as
   skipped, not failed, with the step the interrupt cut as their one operation: `open` for a connect in flight,
   `load`, `diff` or the command for a session in flight, whose close still discards and unlocks what was acquired.
   A target waiting in a retry pause keeps the attempt before it as its last: an unanswered connect (`reached_device`
   false) is skipped, since nothing reached it and the operator stopped the run; any other fault stays a failure
   with its own kind, since the device was reached.
3. A second interrupt reports what is still in flight. It does not abandon records.
4. The run is always closed in the store, with counts for ok, failed and skipped. The report also counts the
   records that could not be kept; a record that could not be written is never the target's failure or cooldown.

## 6. Data model

### 6.1 Store

The schema version is `PRAGMA user_version = 1`. A new, empty database gets this schema;
readers and writers refuse other versions or a mismatched table layout before changing the
file. An unversioned database with tables is incompatible, not an empty database. The error
is an `OSError` containing the path and: "incompatible store schema; use develop's h-ssh-store
to read old stores, or choose a new store path". There is no migration or legacy adapter.

```sql
CREATE TABLE runs (
  id INTEGER PRIMARY KEY,
  started TEXT NOT NULL, finished TEXT,
  mode TEXT NOT NULL, argv TEXT, user TEXT NOT NULL,
  format TEXT, origin TEXT, version TEXT,
  targets INTEGER NOT NULL,
  ok INTEGER, failed INTEGER, skipped INTEGER,
  interrupted INTEGER NOT NULL DEFAULT 0 CHECK (interrupted IN (0, 1)),
  not_kept INTEGER NOT NULL DEFAULT 0 CHECK (not_kept >= 0)
);
CREATE TABLE results (
  run_id INTEGER NOT NULL REFERENCES runs(id),
  seq INTEGER NOT NULL CHECK (seq >= 0), target TEXT NOT NULL, host TEXT NOT NULL,
  driver TEXT NOT NULL, command TEXT NOT NULL,
  target_status TEXT NOT NULL CHECK (target_status IN ('ok', 'failed', 'skipped')),
  ok INTEGER NOT NULL CHECK (ok IN (0, 1)),
  fault TEXT, detail TEXT, reached_device INTEGER CHECK (reached_device IN (0, 1)),
  output TEXT, data TEXT,
  started TEXT NOT NULL, elapsed_ms INTEGER NOT NULL,
  PRIMARY KEY (run_id, target, seq)
);
```

`start_run(spec, started, *, user: str)` assigns an integer ID in SQLite. The recorder
passes its local invoking user for `runs.user`; the store does not discover a second user
or use the device login. `argv` is a JSON array from `RecordSettings.argv`, or SQL NULL
when absent. Payload files are not copied into this row; an inline `-eC` payload is already
part of argv. `format` is the requested `RunSpec.format`, or NULL when unspecified. `origin` and
`version` are optional strings from `RecordSettings`, supplied by the front end; the store
does not discover them. `targets` is the number requested. Until `finish_run(report)`,
`finished` and the three outcome counts are NULL; finalization copies the report's finished
time, counts, interrupted flag and not-kept count. Counts describe target outcomes, not how
many rows survived a recording failure. A missing `finished` means the run was not finalized.

`add(run_id, target, driver, seq, operation, *, status: TargetStatus)` replaces the row at the
same `(run_id, target, seq)`. Sequence numbers follow the target's operation order, starting
at zero. `target_status` is the final target status supplied by the orchestrator on every
operation row; `ok` describes that operation alone. A skipped LOCAL `open` can therefore be
distinguished from a failed LOCAL `open`, and an earlier successful load remains successful
when a later commit fails. `driver` is empty if resolution failed before a driver was known.
`started` and `elapsed_ms` come from the operation, without recomputing either timestamp.

On success, `output` is `Result.output` verbatim, including any `MODE:` prefix, and `data`
is separate JSON text from `Result.data`, or SQL NULL for None. Fault columns are NULL.
On failure, `fault` is `FaultKind.name`, `detail` is the full fault detail, and
`reached_device` is the fault's boolean; `output` and `data` are NULL. No store field is
redacted. The shared pure `hssh.store.json_data(value)` returns a JSON-compatible Python
value, not serialized text: dataclass instances become dictionaries with `asdict`, and
bool, None, dict and list are accepted. Nested values must be JSON values with string keys
and finite numbers. Unsupported values raise `ValueError`. The recorder and front end use
this same converter for structured output; raw output is never parsed to populate `data`.
If `add` cannot convert unsupported `Result.data`, it still writes the row with `data` NULL,
preserving raw output and the operation outcome, then raises a contextual `OSError` naming
the unsupported type. The recorder counts this incomplete record as `not_kept`; the
conversion error never changes the target outcome or escapes from `add` as `ValueError`.

`Store(path, readonly=False)` requires an explicit path. The orchestrator supplies it from
`RecordSettings`; the store imports no orchestrator defaults. The `h-ssh-store` front end
will obtain the default from the orchestrator in slice 3. Writable construction defers
opening and creation to `start_run`, before any device work.
Read-only construction opens an existing compatible store without creating it. SQLite runs
in WAL mode with a 10-second busy timeout, a separate bounded 5-second first-open WAL
wait, `synchronous=NORMAL` and serialized write transactions. Each operation row is committed
in one transaction. NORMAL protects against a process crash; a power loss can lose recent
commits. Store creation/opening failures close every acquired resource. Construction alone
creates no files, and close is idempotent. The writer never deletes a database to undo a
refused run.
`finish_run` and `close` complete the writer interface; SQLite and file failures are exposed
as contextual `OSError`, so the recorder can count lost records without failing the device.
The writer checks the database identity before and after writes and when closing, using a
held directory so a working-directory change or directory rename does not look like a lost
store. A deleted or replaced database is reported even if SQLite could still write its open
file. Each streamed query uses a SQLite snapshot; a later query can see newly committed runs.
Read-only readers never initialize or migrate a store.
An archive that cannot create SQLite sidecars may be read as immutable only with no pending
WAL or journal; changes to its identity, size, modification time or pending sidecars invalidate
the read and are reported at the query boundary and close. Pending WAL data is never skipped.

The reader interfaces in `store.py` return stored column names unchanged:

- `runs(last=20)` streams run rows newest first by timestamp, then ID; None means all,
  zero means no rows, and negative limits are invalid. `last_run_id()` returns the newest
  run's integer ID, or None for an empty store.
- `resolve_run(selector=None)` accepts an integer ID, its exact decimal string, a literal
  unambiguous decimal prefix, or None for the latest run. Exact matches win over prefixes;
  missing, empty, ambiguous and wildcard selectors raise `ValueError`.
- `results(run_id=None, target=None, command=None, ok=None, *, status=None, seq=None,
  order="sequence", limit=None)` streams operation rows. None leaves a filter unrestricted;
  target and command match exactly, and status selects `target_status`. Order is one of
  `sequence` (run ID, target, sequence), `newest` (operation timestamp descending), or
  `slowest` (elapsed milliseconds descending); ties use run ID, target and sequence.
  Timestamps are compared as instants. Limit follows the same rules as `runs`.
- `output(run_id, target, seq=0)` returns one row or raises `ValueError` if absent.
  `compare(before, after, target, seq=0)` returns a logical-line unified diff; a missing or
  failed operation raises `ValueError`, not an empty diff.
- `export(run_id=None, *, format="jsonl", target=None, command=None, ok=None, status=None,
  seq=None)` streams serialized strings in sequence order, one JSONL record or CSV record
  at a time, with a CSV header. It exports every `results` column in schema order; CSV
  retains JSON text in `data`, while JSONL decodes that column to its JSON value. Text and
  newlines are preserved. None selects all runs; callers resolve the latest run explicitly.
  Destination safety checks and terminal rendering belong to the reader command, not this
  serializer. `results` supplies the failed, grep, field, history and slowest commands.

The `h-ssh-store` entry point is `hssh.frontends.store:main_sync`; parsing, rendering,
configuration and default resolution belong to that front end. `store.py` imports no
front-end modules. The reader shares `frontends.settings.store_path` with the writer.
[Reader usage](store.md) covers the commands and exit codes. Display tables stream rows,
and sanitize terminal-bound metadata before shortening; files and pipes retain raw text.
Exports check destination path and inode against the database and its sidecars before
truncation, including hard-link aliases. A closed downstream pipe preserves the command's
known verdict and produces no traceback.

`hssh.paths.validate_device_name(name: str) -> str` and
`path_inside(base: Path, filename: str) -> Path` are the shared file-name helpers for `-eD`
and saved output. The first returns the name or raises `ValueError`: only ASCII letters, digits,
underscore, dot, colon and hyphen, starting with a letter, digit or underscore. The second returns
`base / filename` or raises `ValueError` unless its resolved parent is the resolved base.
Both the payload-file and saved-output callers use these shared helpers.

### 6.2 Audit entry

```json
{"time": "...", "run_id": 42, "user": "...", "target": "R1", "host": "192.0.2.1",
 "driver": "junos@netconf", "action": "load", "payload": "set system host-name R1", "dry_run": false,
 "confirmed_minutes": 10, "comment": "...", "diff": "", "ok": true, "fault": null}
```

`time` is the operation's `started` timestamp. `dry_run` is the inverse of the requested
`EditSettings.apply`; `ok` describes the operation's outcome, not whether a commit was requested.
`fault` is null on success, otherwise an object with `kind` (the fault kind name), `detail` and
`reached_device`. `payload` contains the target's submitted lines joined with newlines on a `load`
entry, including a failed load. It is an empty string when no lines were supplied or the action is not
`load`. The payload, full fault detail, comment and diff are redacted before serialization.
Actions are `load`, `diff`, `commit`, `confirm`, and `probe` (a probe failure that stops an edit).
Confirm runs use `apply=true`.

Each entry is one JSONL line. Appends hold an exclusive file lock through all short writes, reject
symlinks and non-regular files without blocking on FIFOs, and set the file to 0600. Newly created
parent directories are 0700. An append failure raises an `OSError` with the recording path;
the recorder counts it as `not_kept` without changing the device outcome.

Before device work, `probe_append(path)` exercises the same open and lock path with no
content, preserving an existing log. `probe_output_dir(path)` creates private parents,
creates and closes a temporary 0600 file in that directory, then removes it. Neither probe
promises that a later write cannot fail. Both raise contextual `OSError` on failure.
`secure_write(path, text)` saves raw UTF-8 output: it checks a regular file owned by the
current user, locks it and sets 0600 before truncating, then completes all short writes.
It refuses symlinks and FIFOs without blocking, and propagates errors as `OSError`.
The recorder validates the target name and containment through `hssh.paths` before calling
it. Saved output stays one file per target, including batches.

For JSON text in audit fields, the writer parses objects and lists and masks the entire value of a
secret key, including wrapped values. A key is secret when a dialect redaction pattern matches
`json.dumps(key) + ': "x"'`. For other text, the dialect patterns capture the keyword/prefix in
group 1 and an optional suffix in group 3; the writer preserves those groups and masks the value.
JSON scalar replacements retain their quotes. Patterns without capture groups mask the whole match.
The secret vocabulary belongs to the dialect; stored device output is left unchanged.

### 6.3 Safety gate

`SafetyGate(settings)` consumes `SafetySettings`; it defines no run defaults or fault policy.
The orchestrator supplies each target's effective port. State keys are `host|port`, so two
ports on one host are independent. A legacy host-only cooldown holds every port of that
host. A caller supplying no port queries the host as a whole, including its port-specific
cooldowns; the gate does not guess a transport port.

`check_device(target, login=True)` checks cooldown, active reservation and login budget under
one in-process lock, and reserves the device before returning `(True, "ok")`. A refusal
returns `(False, reason)` without a reservation or login count. The sliding window counts
admitted logins in the last 60 seconds using monotonic time. `login=False` still checks
cooldowns and active reservations but neither checks nor consumes the login budget.
`count_login(target)` accounts for a further login inside an existing borrow, using the
same window and `(allowed, reason)` result as admission. It never changes the active
reservation or rechecks cooldowns; a full window refuses the login without counting it.
It raises `OSError` when the gate is closed or has latched an unavailable state. The
orchestrator calls it immediately before reopening a session within the borrow.
`release_device` removes the reservation. `holds(targets)` returns cooldown reasons by
target name without reserving devices or counting logins, so the orchestrator can exclude
held targets before probing. Active reservations and login history are local to the gate
instance; only cooldowns are shared between processes.

`set_cooldown` releases the reservation and records the later of the existing expiry and
wall-clock time plus `cooldown_seconds`. Both settings are finite, non-negative integers;
a zero cooldown adds no hold, and a zero login budget admits no new login. With no safety
file the gate stays in memory. With a file, construction proves persistence usable before
any device work. Construction, cooldown changes and close acquire an exclusive flock on
`<safety_file>.lock`, read and validate disk state, merge disk and memory using the later
expiry, prune expired entries, and write through a temporary file in the same directory.
The temporary file is flushed and fsynced before replacement, then the directory is
fsynced. Admission and `holds` refresh under the same file lock. The state and lock files
are regular owner-only 0600 files, symlinks and FIFOs are refused, and newly created parent
directories are 0700. Temporary files and descriptors are released on failure.

The file is a JSON object mapping keys to finite Unix expiry timestamps. A missing or
empty file is initially empty; legacy null expiries mean no hold. Invalid JSON, a non-object
root, or a non-numeric/non-finite expiry is preserved by moving the file to
`<safety_file>.corrupt`. That marker prevents further use; inspect and repair the state and
remove the marker before starting a new gate. Existing `.corrupt` evidence is not overwritten.
State, lock, and persistence errors raise contextual `OSError`; there is no unlocked or
in-memory fallback. After such an error, the instance stays unavailable for new admissions
until it is replaced. Close prunes and persists healthy state, always clears in-memory active
reservations and login history, and is idempotent. The orchestrator owns the resulting
LOCAL refusal, reporting and cooldown policy; device outcomes are not rewritten by the gate.

## 7. Security

- **Credentials:** an SSH agent or keys through the communicator's library, `HSSH_PASSWORD`, or an
  interactive prompt. Passwords never appear in arguments, in the environment of child processes, in
  logs, in the store, or in the audit log.
- **Redaction:** the recorder redacts secrets from the audit log, using patterns the dialects provide. The
  store keeps device output as received, and is created owner-only.
- **Host keys:** each communicator uses its library's host-key verification under one policy setting:
  `off` (default), `accept-new` or `strict`.
- **Files:** the store, its SQLite sidecars, the audit log, logs and saved output are made
  0600; newly created directories are 0700 and existing directory permissions are preserved.
  Recording files must be regular files owned by the current user; symlinks and FIFOs are
  refused. The store directory must also belong to that user and must not be writable by
  others unless it has the sticky bit, because SQLite reopens the path itself.

## 8. Extensibility

- **New vendor:** add a dialect module and register `vendor@transport` drivers for the transports it
  supports.
- **New transport:** add a communicator implementing section 4.1, declare its capabilities, default port and
  banner, and register drivers.
- **External packages** register through the `hssh.drivers` entry point group. A contract test suite
  verifies any communicator against section 4.

## 9. Testing

| Level | Scope | Against |
|---|---|---|
| Unit | Orchestrator policy, edit lifecycle, cancellation, recorder | a fake communicator |
| Contract | Each communicator against section 4: results, fault kinds, `reached_device` | local fake servers and stubbed libraries |
| Dialect | Prompt, refusal and warning patterns | recorded device output |
| Fleet | Real workloads at scale: shows, batches, edits, commits, confirm, interrupts, unreachable devices | a fleet of virtual network devices |

Each test covers one behaviour. Behaviour that the unit and contract levels can't settle is decided on the
fleet.

## 10. Package layout

```
h-app/hssh/
├── orchestrator/   scheduler.py  policy.py  lifecycle.py  sessions.py  probe.py  recorder.py
├── communicators/  base.py  netconf.py  ssh.py  openssh.py  telnet.py  cli_engine.py
├── dialects/       base.py  junos.py  ios.py  nxos.py  eos.py  generic.py
├── drivers.py      registry and entry points
├── frontends/      cli.py  fleet.py  runfile.py  profiles.py  store.py  settings.py
├── model.py        Target, RunSpec, Result, Fault, RunReport
├── store.py        writer, streaming queries and read-only archives
├── screen.py       terminal-only rendering helpers
├── audit.py
├── paths.py        shared target file names and containment
└── safety.py       safety gate state
```
