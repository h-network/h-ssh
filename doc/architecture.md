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
- **Safe changes.** Dry-run by default, commit-confirmed support, rollback, and a per-device safety gate.
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
  defaults
- builds a `RunSpec`
- passes the `RunSpec` to the orchestrator and renders the `RunReport` it returns

Front ends make no decisions about devices. A behaviour available in the CLI is available in the library
through the same `RunSpec`.

`--every` is a front-end loop. It submits the same `RunSpec` at an interval and renders the differences
between reports.

### 3.2 Orchestrator

The orchestrator executes a `RunSpec` and owns all policy.

| Part | Responsibility |
|---|---|
| Scheduler | Expands targets, runs them in parallel up to the worker limit, and keeps the order of results stable |
| Policy | Maps each `Fault` to an action: retry, fail, skip, or cool down. Applies the safety gate |
| Edit lifecycle | Runs the edit state machine (section 5.3), including dry-run, commit-confirmed, confirm and rollback |
| Session manager | Opens, reuses and closes sessions. Pooling across calls is a session-manager option, not a communicator feature |
| Probe | Optional pre-flight reachability check per target. Its outcome is expressed as the same fault kinds |
| Cancellation | Handles interruption (section 5.4) |
| Recorder | Writes every result to the store and every change to the audit log, with redaction |

### 3.3 Driver registry

A driver is a pair: a dialect and a communicator, named `dialect@transport`, for example `junos@netconf`
or `ios@ssh`. The registry:

- holds the built-in drivers
- loads third-party drivers from the `hssh.drivers` entry point group
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

- opens and closes sessions, using its library's own connection, timeout and host-key handling
- executes one operation per call
- converts library errors into a `Fault` of the right kind, keeping the library's message as detail
- reports whether anything reached the device before a failure

A communicator does not retry, apply policy, write records, or keep state outside its session.

CLI-driven communicators (`ssh`, `openssh`, `telnet`) share one **CLI engine**. The engine drives an
interactive channel: login, prompt detection, paging, command execution and line-by-line configuration.
It reads vendor behaviour from the dialect.

### 3.5 Dialects

A dialect describes one vendor's CLI behaviour as data and small parsing hooks:

- the prompt pattern and paging control
- the refusal and warning patterns
- how to enter and leave configuration mode, and how to commit, if the vendor has a candidate model
- the read-command rule, deciding which commands are safe to retry
- a shortcut library of named commands

Dialects contain no I/O and no policy.

### 3.6 Result store

One SQLite database, `./h-ssh.db` by default. The recorder writes. `h-ssh-store` reads: it lists
runs, shows output, compares results and exports. The schema is in section 6.

### 3.7 Audit log

An append-only JSONL file. One entry per action that changed or could change a device, including dry
runs. The format is in section 6.

## 4. Interfaces

### 4.1 Communicator interface

```python
class Communicator(Protocol):
    capabilities: frozenset[str]          # e.g. {"show", "batch", "edit", "commit_confirmed", "rollback"}

    def open(self, target: Target, creds: Credentials, timeouts: Timeouts) -> Session: ...
    def close(self, session: Session) -> None: ...

    def show(self, session: Session, command: str) -> Result: ...
    def structured(self, session: Session, rpc: str, fmt: str) -> Result: ...   # NETCONF only

    def load(self, session: Session, lines: list[str]) -> Result: ...           # candidate or line-by-line
    def diff(self, session: Session) -> Result: ...
    def commit(self, session: Session, confirmed_minutes: int | None, comment: str | None) -> Result: ...
    def confirm(self, session: Session) -> Result: ...
    def rollback(self, session: Session, index: int = 0) -> Result: ...
    def commit_history(self, session: Session) -> Result: ...
```

Batch execution is the orchestrator calling `show` repeatedly on one session.

### 4.2 Result

```python
@dataclass(frozen=True)
class Result:
    output: str                  # device output as received
    data: object | None = None   # parsed structure, when the operation returns one
    elapsed: float = 0.0
```

### 4.3 Fault

```python
class FaultKind(Enum):
    UNREACHABLE      # no connection, or no response before login
    AUTH             # credentials rejected
    HOST_KEY         # host key rejected by the communicator's library
    TIMEOUT          # no response within the timeout during a session
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
| `UNREACHABLE`, `TIMEOUT` before login | retry, then fail | retry, then fail | n/a |
| `AUTH`, `HOST_KEY` | fail | fail | n/a |
| `TIMEOUT`, `SESSION_LOST` in session | retry | fail | fail, cool down |
| `REFUSED`, `COMMIT_FAILED` | fail | fail, cool down | fail, cool down |
| `OUTCOME_UNKNOWN` | n/a | n/a | fail, never retried, flagged for manual check |
| `UNSUPPORTED`, `LOCAL` | fail | fail | fail |

The retry count, pauses and cooldown period are policy settings, not communicator settings.

## 5. Execution model

### 5.1 RunSpec

A `RunSpec` holds: the targets, the mode (`show`, `batch`, `structured`, `edit`, `rollback`, `confirm`,
`commit_status`), the commands or configuration lines, credentials, timeouts, the worker limit, the safety
settings, and the recording settings.

### 5.2 Concurrency

The orchestrator runs on asyncio. Blocking libraries such as paramiko and PyEZ run in a thread pool sized
to the worker limit. Each target is one task. A target's operations run in order on one session. Targets
run independently, and one target's failure does not affect another's.

### 5.3 Edit lifecycle

```
OPEN → LOAD → DIFF ──(dry run)──────────────────────────────► CLOSE
                 └─(apply)→ COMMIT ─(confirmed N)→ PENDING ─► CLOSE
                                                     │
                                         later run: CONFIRM or ROLLBACK
```

- **Dry run** is the default: load, diff, discard. Nothing is committed.
- **Apply** requires explicit confirmation, either `-y` or the interactive prompt after the diff preview.
- **Commit-confirmed** leaves a pending commit. The report lists the devices with a pending commit and the
  command that confirms them.
- On any fault after `LOAD`, the orchestrator discards the candidate, or rolls back where the dialect has
  no candidate.
- The safety gate is consulted before `OPEN` for edits. Cooldowns persist across runs in the safety file.

### 5.4 Cancellation

1. On the first interrupt, the scheduler starts no new targets. Targets that have not started are recorded
   as skipped.
2. Targets past `COMMIT` are waited for and recorded. Other in-flight targets are cancelled and recorded.
3. A second interrupt reports what is still in flight. It does not abandon records.
4. The run is always closed in the store, with counts for ok, failed and skipped.

## 6. Data model

### 6.1 Store

```sql
runs(
  id INTEGER PRIMARY KEY, started TEXT, finished TEXT, mode TEXT, argv TEXT,
  targets INTEGER, ok INTEGER, failed INTEGER, skipped INTEGER
)
results(
  run_id INTEGER REFERENCES runs(id), seq INTEGER, target TEXT, host TEXT,
  driver TEXT, command TEXT, ok INTEGER, fault TEXT, detail TEXT,
  output TEXT, started TEXT, elapsed REAL,
  PRIMARY KEY (run_id, target, seq)
)
```

SQLite runs in WAL mode with a busy timeout. Each run writes in its own transactions.

### 6.2 Audit entry

```json
{"time": "...", "run_id": 42, "user": "...", "target": "R1", "host": "192.0.2.1",
 "driver": "junos@netconf", "action": "commit", "dry_run": false,
 "confirmed_minutes": 10, "comment": "...", "diff": "...", "ok": true, "fault": null}
```

## 7. Security

- **Credentials:** an SSH agent or keys through the communicator's library, `HSSH_PASSWORD`, or an
  interactive prompt. Passwords never appear in arguments, in the environment of child processes, in
  logs, in the store, or in the audit log.
- **Redaction:** the recorder redacts secrets from output written to logs and the audit log, using
  patterns the dialects provide. The store keeps device output as received, and is created owner-only.
- **Host keys:** each communicator uses its library's host-key verification under one policy setting:
  `accept-new` (default), `strict` or `off`.
- **Files:** the store, the audit log, logs and saved output are created with mode 0600, in directories
  created with mode 0700.

## 8. Extensibility

- **New vendor:** add a dialect module and register `vendor@transport` drivers for the transports it
  supports.
- **New transport:** add a communicator implementing section 4.1, declare its capabilities, and register
  drivers.
- **External packages** register through the `hssh.drivers` entry point group. A contract test suite
  verifies any communicator against section 4.

## 9. Testing

| Level | Scope | Against |
|---|---|---|
| Unit | Orchestrator policy, edit lifecycle, cancellation, recorder | a fake communicator |
| Contract | Each communicator against section 4: results, fault kinds, `reached_device` | local fake servers and stubbed libraries |
| Dialect | Prompt, refusal and warning patterns | recorded device output |
| Fleet | Real workloads at scale: shows, batches, edits, commits, confirm, rollback, interrupts, unreachable devices | a fleet of virtual network devices |

Each test covers one behaviour. Behaviour that the unit and contract levels can't settle is decided on the
fleet.

## 10. Package layout

```
h-app/hssh/
├── orchestrator/   scheduler.py  policy.py  lifecycle.py  sessions.py  probe.py  recorder.py
├── communicators/  base.py  netconf.py  ssh.py  openssh.py  telnet.py  cli_engine.py
├── dialects/       base.py  junos.py  ios.py  nxos.py  eos.py  generic.py
├── drivers.py      registry and entry points
├── frontends/      cli.py  fleet.py  runfile.py  profiles.py
├── model.py        Target, RunSpec, Result, Fault, RunReport
├── store.py        writer, and the h-ssh-store reader
├── audit.py
└── safety.py       safety gate state
```
