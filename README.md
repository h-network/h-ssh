<div align="center">

<img src="assets/banner.svg" alt="H-SSH // the fleet loop, not the session // h-network" width="600">
 
<br/>

[![License: PolyForm Noncommercial 1.0.0](assets/badges/license.svg)](LICENSE)
![Python 3.10+](assets/badges/python.svg)
![Vendors: junos ssh openssh telnet](assets/badges/vendors.svg)
![Runtime dependencies: paramiko and PyEZ](assets/badges/deps.svg)

</div>

# h-ssh

`h-ssh` runs commands across a fleet of network devices: one device or three hundred, Juniper, any SSH host, or a console
still speaking telnet. Devices are worked in parallel, results are collected per device, and one dead box does not sink a show
run; an edit run checks every target is reachable first and refuses to start a partial deployment.

The per-device session is a solved problem; what is left is everything around it: the thread pool, per-device result collection, a rate
limiter (`--safety-file`) so a router that already failed is not hammered, and a record of what changed (`--audit-log`). That is
the part h-ssh provides.

On Junos, everything goes through PyEZ over NETCONF, reads and writes alike, which gives one session, real RPC errors, and the lock, diff
and rollback that config changes need. Every edit is checked for reachability and prompts before it commits; with `--audit-log` it
lands in a JSONL audit trail.
`--commit-confirmed` puts the device back the way it was if you never confirm.

## Features

- **Four transports, one interface.** Juniper (PyEZ over NETCONF), any SSH host through paramiko or the system `ssh` binary, and raw-socket telnet with IOS-, Junos-, Arista- and NX-OS-flavoured prompt handling. Same flags whichever you point it at; the ones only a Junos transport can honour (`--dry-run` on an edit, `--show-diff`, `--commit-confirmed`, and over NETCONF `--comment`, `--format`, `--rollback`, `--commit-status`) are refused on the others before anything is sent, never faked.
- **Parallel by default.** Devices are worked concurrently behind an `asyncio` semaphore, `--workers 8` out of the box. 3 routers, 3 show commands, ~350 ms end to end.
- **One command or many, one device or many.** `--batch` runs several commands per device on a single connection; `--job` takes a JSON file with different commands — and different modes — per device, readable from a file or stdin.
- **Writes are gated.** Pre-flight reachability check, `y/N` confirmation, `--dry-run` that shows the diff without committing and `--commit-confirmed N` for changes that undo themselves unless you confirm within N minutes (both Junos), and an opt-in per-device rate limit and cooldown (`--safety-file`).
- **Templates instead of memorised syntax.** `-sC bgp` resolves through a per-vendor JSON template library — *per target*, so the same shortcut sends a Junos router and an EOS switch each their own command. Drop your own in `~/.h-ssh/commands/{dialect}.json` (`junos`, `eos`, `none`) to override.
- **Built to be scripted.** `--json` on stdout, a structured summary line on stderr, meaningful exit codes, and credentials from `HSSH_USER` / `HSSH_PASSWORD` — or import `hssh` and skip the CLI entirely. A whole fleet run fits in one YAML file (`--run fleet.yaml`) that a pipeline step or a jump-host session runs as it is.
- **Built for a maintenance, not just a run.** A session pool keeps one NETCONF session per router open for a whole script; `rpc()` and `--format json|xml` return the router's own data instead of CLI text; `begin()` holds a diffed candidate open until a gate decides; `--rollback N`, commit comments, `--commit-status` and `guarded_commit()` cover the commit-confirmed lifecycle without a `| match` in sight.
- **Two runtime dependencies — or none.** `paramiko` and `junos-eznc` come with the package. Telnet is a raw socket (no stdlib `telnetlib`, so it still works on Python 3.13+), and the `openssh` transport drives the system `ssh` binary, so a checkout on a locked-down jump host with nothing installable still runs shows and edits over `ssh`.

## How it works

```
  hosts / devices.csv / --job                 per device, up to --workers at once
  ──────────────────────────────────           ─────────────────────────────────────
                    │                          ┌─ junos    PyEZ over NETCONF (830)
                    ▼                          │           show/edit → PyEZ NETCONF
        ┌───────────────────────┐              │                  lock → load → diff
        │ safety gate (opt-in)  │              │                  → commit → unlock
        │ rate limit 10/device  │──▶ workers ──┼─ ssh      exec_command
        │ cooldown 120s on fail │              │
        │ --safety-file, flock'd│              ├─ openssh  the ssh binary, no deps
        └───────────────────────┘              └─ telnet   raw TCP + prompt match
                    │                                          │
                    └──────────── every edit ──────────────────┴──▶ --audit-log (JSONL)
```

On Junos, show commands run through PyEZ `Device.cli()` over one NETCONF session (a batch shares it), and the NETCONF port defaults to 830 for every Junos call; set the target's port to use NETCONF on 22. Config changes lock the candidate, load, diff, run `commit_check`, commit, and unlock, rolling back if any step fails. Confirming a commit-confirmed (`-eC "commit"`) first reads the commit history: with no commit-confirmed waiting (the timer expired, or it was confirmed already) the device fails with *nothing to confirm* and nothing is sent, because a plain commit there would hide that the change is already gone. It locks too, so another user's uncommitted edits in the shared candidate refuse it — nothing sent, retried like any other lock refusal — instead of riding along with the confirmation. The "don't forget to confirm" reminder prints only when at least one device actually armed a timer. A commit whose reply never arrives is reported as *outcome unknown* and is never retried or rolled back automatically — check the device (and any commit-confirmed timer) first. The NETCONF session does not verify the router's host key by default (the management network is the trusted path, and a re-keyed router must not stop a maintenance); `HSSH_NETCONF_HOSTKEY=yes` turns verification against `~/.ssh/known_hosts` on for a jump host on a path that is not trusted. With a password, no `~/.ssh/id_*` key and no agent is tried first. A session that does not open is reported by what happened, not by PyEZ's label (which calls anything that fails within 3 s *refused*): `connection refused by HOST:PORT`, `connect to HOST:PORT timed out after Ns`, `HOST:PORT is not an SSH server: the banner is not text`, `HOST:PORT dropped the session before login (sshd connection limit?)`, `no SSH banner from HOST:PORT within Ns (sshd busy, or filtered)`, `host key verification failed`, `authentication failed for USER at HOST:PORT`, `cannot resolve HOST`. A `delete` of a statement the device does not have is a no-op (`warning: statement not found` is the one load warning that is ignored, so a broadcast of deletes stays idempotent); every other warning still fails the device. `--session-timeout` is one deadline for the whole session set-up — TCP connect, SSH banner, key exchange, authentication — not PyEZ's connect timeout followed by paramiko's own 15 s banner, 15 s key-exchange and 30 s authentication timeouts, so a router that accepts TCP and then says nothing costs what you asked for. An IPv6 literal cannot be used on this transport at all (PyEZ refuses the bare form, ncclient cannot resolve the bracketed one); it is reported once, as such.

## Install

One line, no package manager. It needs `python3` 3.10 or newer with its venv module (Debian/Ubuntu:
`sudo apt install python3-venv`) and `git`:

```bash
curl -fsSL https://raw.githubusercontent.com/h-network/h-ssh/develop/install.sh | sh
h-ssh --list-vendors
```

The installer puts h-ssh in a Python environment of its own, `~/.h-ssh/venv`, with every transport
(paramiko and PyEZ come with it), and links `h-ssh` and `h-ssh-store` into `~/.local/bin`, creating
that directory when it is missing; if it is not on your `PATH` yet the script says so and how to add
it. Your config, inventory and stores live next to the environment under `~/.h-ssh`, and pip's download
cache lands in `~/.cache/pip`. Running the same line again upgrades, whatever the version number says.
It installs the `develop` branch; a knob on the `sh` side of the pipe picks another branch or tag:
`curl -fsSL … | H_SSH_REF=main sh` (`H_SSH_HOME`, `H_SSH_BIN` and `H_SSH_PYTHON` are the others, see
the script's header). Removing it:

```bash
curl -fsSL https://raw.githubusercontent.com/h-network/h-ssh/develop/install.sh | sh -s -- --uninstall
```

takes the environment and the two links away and leaves `~/.h-ssh` otherwise alone; it never touches
an `h-ssh` in `~/.local/bin` that it did not put there (a pipx or uv install, your own wrapper), and
neither does an install. Read the script first if you like: a page of POSIX sh that does what this
paragraph says.

If you already use [pipx](https://pipx.pypa.io) or [uv](https://docs.astral.sh/uv/), the same thing in
their words: `pipx install git+https://github.com/h-network/h-ssh.git` or
`uv tool install git+https://github.com/h-network/h-ssh.git`.

For working on h-ssh itself:

```bash
git clone https://github.com/h-network/h-ssh.git && cd h-ssh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'           # the package, editable, plus pytest
```

The checkout's `./h-app/h-ssh.py` is the same CLI without installing, on an interpreter that has
`paramiko` and `junos-eznc`; the `openssh` and `telnet` transports need neither.

## Quick start

```bash
# a show on two routers typed bare: the host is the name, --transport the driver; you are the user
# you are logged in as, the password is asked for (keys and agents need nothing)
h-ssh --transport junos 10.0.1.1 10.0.1.2 -sC bgp

# the same, named, the vendor on the target, as another user
h-ssh --user admin -sC bgp R1:10.0.1.1:junos R2:10.0.1.2:junos

# ... or from a CSV inventory, as JSON (the sample inventory has junos, openssh and ssh rows)
h-ssh --user admin --json -sC "show version" --devices h-app/devices.csv

# compare one command's output across the fleet: each device against the first that answered, in
# target order (bare hosts, then --target; or the inventory's rows)
h-ssh -sC bgp --diff R1:10.0.1.1:junos R2:10.0.1.2:junos

# config change — look before you leap (no host typed: the inventory is ~/.h-ssh/devices.csv, or ./devices.csv)
h-ssh --user admin -eC "set system ntp server 10.0.0.1" --dry-run
h-ssh --user admin -eC "set system ntp server 10.0.0.1" -y

# a change that rolls itself back in 10 minutes unless you confirm
h-ssh --user admin -eB configs/all.set --commit-confirmed 10 -y

# several commands per device, one connection
h-ssh --batch commands.txt R1:10.0.1.1:junos
h-ssh --profile junos-health R1:10.0.1.1:junos     # a named command set, yours or shipped (--list-profiles)

# watch: the same read every 30 s, every tick kept in the store, only what changed is printed
h-ssh -sC "show bgp summary" --every 30 R1:10.0.1.1:junos R2:10.0.1.2:junos

# a console server still speaking telnet
h-ssh -sC "show version" SW1:10.0.0.1:5000:telnet-ios

# every run is kept in ./h-ssh.db, as the devices answered; read it back
h-ssh-store runs
h-ssh-store output R1
```

Targets are typed bare on the command line, before or between the flags. A host alone (`10.0.1.1`, `cr1.example.net`, `[2001:db8::1]`) is a device named after itself on `--transport`; `NAME:HOST`, `NAME:HOST:VENDOR`, `NAME:HOST:PORT` or `NAME:HOST:PORT:VENDOR` name it (`NAME:HOST:VENDOR:PORT` works too, and is what the confirm hint prints), an IPv6 host in brackets, `R1:[2001:db8::1]:junos`. `--target SPEC` is the same thing as a flag (repeatable; it wants the name). With any target typed the inventory file is not read; without one it is `--devices`, else `~/.h-ssh/devices.csv`, else `./devices.csv`. A CSV inventory accepts `name,ip`, `name,ip,vendor` or `name,ip,vendor,port`, or one bare hostname per line; headers or none, and `#` comments, full-line or trailing. A UTF-8 BOM from Excel or Notepad is skipped. A fifth column, a port outside 1..65535 or a port that is not a number is refused naming the row, so a typo never turns into the wrong device.Each device is listed once: the same row twice, one name on two hosts, or one host under two names is refused before anything runs (exit 2, naming the duplicate). A job file may repeat a device (one session per entry), but not use one name for two hosts.

**A target that doesn't declare a vendor gets `--transport`**, which defaults to plain `ssh` — the transport that assumes least, since its show and edit paths are both `exec_command`. Declare `junos` on the target to get NETCONF, or set it once with `--transport junos` (or `transport = junos` in `~/.h-ssh/config`) for an inventory of `name,ip` rows; a vendor on the target itself always wins. Command shortcuts resolve per target against that vendor, so one `-sC bgp` across a mixed inventory sends each device its own command.

### Authentication

```bash
h-ssh --user admin -sC bgp                     # SSH agent / key, or type it at the prompt
export HSSH_USER=admin HSSH_PASSWORD=secret               # a pipeline: from the environment, nothing to type
```

There is no `--password` flag. h-ssh reads `HSSH_PASSWORD` when it is set, which is how a pipeline
hands over the secret for that one process (from a vault, from the scheduler); otherwise, when stdin
is a terminal, it asks, and Enter skips the password for keys or an agent; with neither there is no
password. A variable that is set but empty refuses a pipeline run (exit 2) rather than falling back to
keys without a word. A flag would show the password to every user on the host (`ps`,
`/proc/<pid>/cmdline`), leave it in the shell history, and put it in the command line `--store` keeps.
Your own user password belongs in neither a file nor a shell profile; the environment variable is for
an account made for automation. The same `ps` exposure holds for the
`openssh` transport's commands: each line runs as the `ssh` process's argument, so a config line is
readable from `ps` for the life of that process; push secrets over NETCONF or paramiko, not over
`openssh`.

A password means the same on every transport: it is the credential, and no `~/.ssh/id_*` key and no agent key is offered first (`openssh` passes `PubkeyAuthentication=no` and `IdentitiesOnly=yes`), so a wrong password is a failed login on `junos`, `ssh` and `openssh` alike, never an OK by way of a key. Without a password the keys and the agent are what you log in with.

## Modes

| Flag | Mode | What it does |
|---|---|---|
| `-sC` | Show | Run a show/display command (or a template name). A command that acts on the device (`request …`, `clear …`) is sent once and never retried, and refused under `--format` |
| `-eC` | Edit command | Apply one config line to every target |
| `-eD` | Edit directory | Per-device config from `<NAME>.set` files: blank and full-line `#` comments are skipped, nothing else is touched, so `community ab#12` goes as written. A device without its `<NAME>.set` ends the run before anything is sent (exit 2, naming it); `--allow-missing` skips those devices instead and reports them as skipped (exit 3) |
| `-eB` | Edit broadcast | One config file applied to all targets |
| `--batch` | Batch | Several show commands from a file, one connection per device |
| `--profile` | Batch | The same, by name: a command set of yours in `~/.h-ssh/profiles/NAME.txt`, or one that ships (`junos-health`, `junos-snapshot`); `--list-profiles` shows both. A profile is a batch file, one command per line, `#` comments, the first comment its description |
| `--job` | Job | Per-device commands *and* modes from JSON — file or `-` for stdin |
| `--rollback N` | Rollback | Return every target to rollback N (0–49): the same lock → diff → commit check → commit → unlock as an edit, so `--dry-run` shows the diff of going back and `--commit-confirmed` arms the timer (Junos) |
| `--commit-status` | Commit status | `show system commit` as data per target: sequence, time, user, comment, and the pending commit-confirmed timer (Junos) |
| `--run FILE` | Run file | Any of the above described in one YAML or JSON file: devices, commands, options, outputs. See [Run files](#run-files) |

```json
[
  {"target": "R1:10.0.1.1:junos", "show": "show bgp summary"},
  {"target": "R2:10.0.1.2:junos", "show": "show version"},
  {"target": "R3:10.0.1.3:junos", "edit": "set system host-name R3-new"}
]
```

```bash
./h-app/h-ssh.py --user admin --job jobs.json --json -y
cat jobs.json | ./h-app/h-ssh.py --user admin --job - --json -y   # the job is on stdin, so an edit cannot be confirmed there
```

An entry may also carry `"port": 830` to override the target's port. A job with an edit entry asks the usual
`y/N` unless `-y` is given, and the question goes to stdout, so a `--json` run wants `-y`.

A device may appear in more than one entry. Its entries run one after another, in file order, so a
show listed after an edit sees the edit, and each is audited with its own mode and payload.

### Watching: `--every`

`--every SECONDS` runs the same read again, SECONDS after the previous tick finished, until Ctrl-C or
`--times N`. Reads only (`-sC`, `--batch`, `--profile`), and the store must be on: every tick is a run
in the store, and the ticks are compared through it. The screen gets one line per tick and, for every
device whose reply changed since the tick before, the difference:

```
tick 1 14:02:10: 250 OK, 0 failed; baseline kept as run 20261025-140210-3f1a
tick 2 14:02:43: 250 OK, 0 failed, 1 changed
--- cr17: show bgp summary
  --- 2026-10-25T14:02:10
  +++ 2026-10-25T14:02:43
  @@ -3,2 +3,2 @@
  -10.9.9.8  65000  Establ
  +10.9.9.8  65000  Active
```

A device that fails on a tick shows as `OK -> FAIL (reason)`. The structured summary line still goes to
stderr once per tick, and any two ticks can be compared later with `h-ssh-store diff DEVICE RUN_A RUN_B`.
Ctrl-C between ticks stops the watch and says how many ticks are kept.

## Transports

A target names a *driver*: one dialect (what the device speaks) on one transport (how it is reached).
The canonical name is `dialect@transport` — `junos@netconf`, `ios@telnet` — and the names in the
table below are its aliases; both work in a target, a CSV and a job file. The driver declares what it
can be asked (`hssh.drivers`): the runner refuses `--rollback`, `--format`, `--comment`, `--dry-run`
on an edit or `--commit-confirmed` where the driver does not list them, before any device is touched.

| Vendor | Transport | Library | Show | Edit |
|---|---|---|---|---|
| `junos` | NETCONF | junos-eznc | PyEZ `Device.cli()` | PyEZ lock/load/diff/commit |
| `ssh` | SSH | paramiko | `exec_command` | `exec_command` |
| `openssh` | OpenSSH client | built-in | `ssh host cmd` | `ssh host cmd` |
| `junos@ssh` | SSH, Junos CLI | paramiko | exec channel | shell: `configure exclusive` / `show \| compare` / `commit`, `--dry-run`, `--commit-confirmed`, `-eC commit` |
| `ios@ssh`, `nxos@ssh` | SSH, IOS-shaped CLI | paramiko | exec channel | shell: `configure terminal` … `end` |
| `eos@ssh` | SSH, EOS CLI | paramiko | exec channel, `--structured` via `\| json` | shell: `configure terminal` … `end` |
| `junos@openssh`, `ios@openssh`, `nxos@openssh`, `eos@openssh` | the same dialects over the OpenSSH binary | built-in | `ssh host cmd` (`\| json` for `eos@openssh --structured`) | `ssh -tt host` shell, the same edit sequences |
| `telnet` | Raw socket | built-in | raw TCP | config mode |
| `telnet-ios` | Raw socket, IOS prompts | built-in | raw TCP | `configure terminal` |
| `telnet-junos` | Raw socket, Junos prompts | built-in | raw TCP | `configure exclusive` / `commit` |
| `telnet-arista` | Raw socket, EOS prompts | built-in | raw TCP | `configure terminal` |
| `telnet-nxos` | Raw socket, NX-OS prompts | built-in | raw TCP | `configure terminal` |

Every transport runs a batch on one session per device.

A dialect over SSH or telnet is typed at by one CLI engine (`hssh/transports/cli.py`): it logs in,
learns the device's own prompt, answers paging, and runs the edit sequence the dialect describes (a
candidate diffed and committed or discarded for Junos, lines applied in config mode for the IOS-shaped
ones). Shows over SSH use an exec channel, one command per channel; only edits and confirms open a
shell. Over the OpenSSH binary the shell is `ssh -tt`, with a password still handed over through
`SSH_ASKPASS`, never typed at a prompt. The plain `ssh`/`openssh` drivers (dialect `none`) never open
a shell.

`h-ssh --list-vendors` prints the registry: every driver a target may name, its aliases, transport,
dialect, the formats `--format` can ask it for, what it supports, and where it came from (`built-in`,
or the package that registered it: see [Adding a vendor](#adding-a-vendor)). `h-ssh --list-commands
--transport junos` lists a dialect's shortcut library the same way.

Telnet is a prompt match on a raw socket, so it is strict about what it has not seen. A read that reaches
its timeout or loses the connection is an error, never a partial reply passed off as the device's answer,
and a `login:`/`Password:` prompt back after the password is a failed login, reported once — not the
command typed in as a username. A port that prints nothing until Enter — a console-server line left at
a prompt — gets one Enter once the session timeout is up, before silence counts as a failed login.
The prompt is learned at login (`lab@R1` or `Router`, with its config-mode suffix) and looked for on
the last line of a reply only, never on the echo of what was typed, so a description ending in `>` or
a community ending in `#` cannot be taken for the prompt and shift every later reply.
`telnet-junos` edits enter `configure exclusive`, as the NETCONF driver's lock does: a refused lock is
reported before any `set` line is sent, and `commit` and the dry run's `rollback 0` only ever touch
this session's candidate, never another user's pending changes. `-eC "commit"` confirms a pending
commit-confirmed with one bare `commit` in exclusive mode; a `commit` line inside a config payload is
refused before the device is contacted. A commit whose reply never arrives is
*outcome unknown* here too; one answered with `commit complete` that then takes the session with it — a
management address, the telnet service — is still reported as committed, the closed session releasing
the lock.

### `ssh` — paramiko, for anything that speaks SSH

The default transport runs each line as its own `exec_command`. A command that exits non-zero is a
failure, not output: an edit stops at that line and reports it, a batch marks the entry `ok: false`
with the first line the device said about it (stderr, or stdout where the device puts its errors).

Host keys are pinned on first contact in `~/.h-ssh/known_hosts` (created 0600), and
`~/.ssh/known_hosts` is honoured too. The policy is the same `HSSH_HOST_KEY_POLICY` the `openssh`
transport reads: `accept-new` (default) pins an unknown host, `yes` refuses one, `no` only warns.
A host whose key has changed is refused under every policy, before any credential is sent — after
a re-image, remove its line from `~/.h-ssh/known_hosts`.

### `openssh` — for hosts where you cannot install anything

`openssh` needs no Python packages at all. It drives the system `ssh` binary: `subprocess` for key
auth, and `SSH_ASKPASS` for password auth, because OpenSSH refuses to read a password from a pipe.
The password reaches OpenSSH through a helper it execs itself, on a channel the session never
touches — never through the terminal, where device output and auth prompts would share one stream.
Batch work reuses one TCP connection and one authentication through OpenSSH connection multiplexing
(`ControlMaster`), so each command still comes back cleanly separated. OpenSSH's `ConnectTimeout` bounds the TCP connect and the banner, but nothing in OpenSSH bounds a key exchange that hangs after the banner, so the driver keeps its own clock: ssh's `-v` log (written to a private file with `-E`, never mixed into the device's output) says when the session is up, a session that is not up within `--session-timeout` is abandoned then (`no SSH session to HOST within Ns: the banner came, but key exchange or authentication did not finish`), and `--command-timeout` starts the moment the session is up, not at process start. ssh's own diagnostics come from that log; the `STDERR:` block of an output is the device's.

Password auth needs OpenSSH 8.4+ for `SSH_ASKPASS_REQUIRE=force`; older clients are refused rather
than silently falling back to a terminal prompt. Key auth has no such floor.

Use it on locked-down jump hosts — no package index, no `ensurepip`, no root — where `pip install
paramiko` is not on the table but `ssh` is already there:

```bash
./h-app/h-ssh.py --target R1:10.0.1.1:openssh -sC "show version" --user admin
```

It inherits your `~/.ssh/config`, keys, agent and `known_hosts`, so jump-host `ProxyJump` stanzas and
per-host identities work with no extra flags. Host key policy defaults to `accept-new`; override with
`HSSH_HOST_KEY_POLICY=yes` (strict) or `no` (skip).

Two limits, both deliberate: `--structured` has no bindings here, and `--commit-confirmed` is
rejected rather than silently ignored — as it is on every transport but `junos` and `telnet-junos`,
the two that can arm a rollback timer; dropping the timer without saying so would be worse than refusing.

Edits run in an EOS configure session: the lines load into the session, its diff comes back, and
`commit` makes them live together. A rejected line aborts the session and leaves running-config as
it was; `NO CHANGES` means the session diff was empty and nothing was committed.

## Adding a vendor

A vendor is a driver: a dialect (what the device speaks) on a transport (how it is reached). The
built-ins are declared in `hssh/drivers/__init__.py`; a package installed next to h-ssh declares its
own through the `hssh.drivers` entry-point group, so an internal package can ship a dialect, or a
driver pairing one with an existing transport, without a fork of h-ssh. Four pieces and one test run.

**A dialect file.** A `Dialect` (`hssh/dialects/base.py`) is everything h-ssh knows about the device
and nothing about connections; `hssh/dialects/ios.py` and `none.py` are the smallest built-in ones.

| Field | What it is |
|---|---|
| `name` | the half of a driver name before the `@` (`ios` in `ios@ssh`), and the stem of the operator's shortcut file |
| `title`, `description` | the name as printed to the operator, and one line on the dialect |
| `refused` | a compiled regex (`re.MULTILINE`) for a line in which the CLI refused a command, `^\s*% ` for IOS. Every text transport reads replies with it: a show whose reply opens with such a line is a failure, not output, and an edit stops at the line that got one. A dialect on `ssh`, `openssh` or `telnet` must have one |
| `is_read` | `command -> bool`: a read is retried and allowed under `--format`, anything else is sent once. The default takes `show …` and `get-*` |
| `check_edit` | `(payload, allow_commit) -> (ok, why_not)`: the guard an edit payload must pass before any device is contacted (Junos's set-syntax rule; `allow_commit` is False for `-eD`/`-eB` files). `None` means no guard |
| `cli` | a `CliSyntax`, for edits over a transport that types at the device (a shell on `ssh` or `openssh`, `telnet`): the prompt regexes (`prompt`, `prompt_name`, `prompt_tail`), `config_enter`/`config_exit`, and for a dialect with a candidate configuration `compare`, `discard` and `commit` (plus `context`, the `[edit]` line Junos prints with its prompt). `None`: the dialect shows over those transports but cannot edit |
| `commit_pending` | a regex whose group 1 is the minutes left on a pending commit-confirmed, as `show system commit` prints them; `-eC commit` confirms only when it finds one |
| `shortcuts` | the stem of a shipped library, `hssh/dialects/<stem>.json` — built-in dialects only, see below |

```python
# acme_hssh/__init__.py — an IOS-shaped switch, shows and edits over paramiko
import re
from hssh import drivers
from hssh.dialects.base import CliSyntax, Dialect
from hssh.drivers import Driver

CLI = CliSyntax(prompt=re.compile(r"[\w\-\.]+(\([^\s()]+\))?[>#]\s*$"),
                prompt_name=re.compile(r"^([\w\-\.]+)(\([^\s()]+\))?[>#]\s*$"),
                prompt_tail=r"(\([^\s()]+\))?[>#]\s*$",
                config_enter="configure terminal", config_exit="end")
DIALECT = Dialect("acme", "AcmeOS", "Acme switches: an IOS-shaped CLI",
                  refused=re.compile(r"^\s*% ", re.M), cli=CLI)

DRIVERS = [Driver(DIALECT, drivers.SSH, frozenset({"show", "show_batch", "edit"}))]
```

**A `Driver` on a transport.** `Driver(dialect, transport, supports, aliases=())`. The transport is one
of `drivers.SSH`, `drivers.OPENSSH`, `drivers.NETCONF` and `drivers.TELNET` (frozen: it takes a
dialect, nothing else), or a `Transport` of the package's own whose `module` meets the contract below.
`supports` is the set of words the runner may ask for: `show`, `show_batch`, `show_structured`, `rpc`,
`edit`, `rollback`, `confirm`, `commit_status`, and the policies `dry_run`, `commit_confirmed` and
`comment`. A word the driver does not list is refused by name before any device is touched, so list
what the transport's module really does for this dialect. The `ssh` and `openssh` modules show on an
exec channel for any dialect with a `refused`, edit through the CLI engine for one with a `cli`, and
need a candidate (`compare`, `discard`, `commit`) for `dry_run`, `commit_confirmed` and `confirm`;
`show_structured` there is EOS's `| json`, and `rpc`, `rollback`, `commit_status` and `comment` are
NETCONF's. `Driver` itself refuses nonsense (`rpc` on a text-only transport, a policy without `edit`).
An alias is another name a target may carry (`telnet-ios` for `ios@telnet`) and must be free.

**A JSON of shortcuts.** `-sC bgp` resolves against the dialect's library: for a built-in dialect the
file next to it, `hssh/dialects/<dialect>.json`, and for every dialect the operator's
`~/.h-ssh/commands/<dialect>.json` and `~/.h-ssh/commands/<vendor as typed>.json` on top, later files
overriding earlier entries. A built-in dialect names its library by stem (`shortcuts="junos"`); a
dialect from another package names its own file by path (`shortcuts=str(Path(__file__).with_name("acme.json"))`),
and the operator's `~/.h-ssh/commands/acme.json` still goes on top. The format is
`hssh/dialects/junos.json`'s — a name, the command, a description, and for NETCONF an optional
`structured` binding:

```json
{
  "version": {"command": "show version", "description": "Software version and uptime"},
  "bgp": {"command": "show ip bgp summary", "description": "BGP neighbor summary"}
}
```

**The entry point.** In the package's own `pyproject.toml`:

```toml
[project.entry-points."hssh.drivers"]
acme = "acme_hssh:DRIVERS"
```

It names a `Driver`, a list of them, or a callable returning either. Installed next to h-ssh, the
package's drivers load after the built-ins, and `acme@ssh` works in a target, a CSV row, a job and a
run file like any built-in name (`--transport` keeps its four choices). `h-ssh --list-vendors` shows
it with where it came from:

```console
$ h-ssh --list-vendors
name           aliases  transport  dialect  formats        supports                                      source
junos@netconf  junos    netconf    junos    text,xml,json  comment commit_confirmed commit_status …      built-in
none@ssh       ssh      ssh        none     text           edit show show_batch                          built-in
…
acme@ssh       -        ssh        acme     text           edit show show_batch                          acme-hssh (entry point acme)
```

An entry point is taken whole or not at all. One whose import raises, that hands over something that is
not a `Driver`, or that claims a name or alias already registered is listed by name at the end of that
output — `broken entry point 'acme': ImportError: …` — never as a traceback, and the rest still load.
The registry is `hssh.drivers`: `DRIVERS`, `SOURCES` and `BROKEN` are what `--list-vendors` prints,
and `load()` rebuilds them.

**The contract test run.** `pytest h-app/tests/drivers/test_contract.py` puts every registered driver
through `hssh.drivers.contract.violations()`: the module behind the driver has an `AVAILABLE` flag and
a function for each capability declared — `show`, `show_batch`, `edit`, … — that takes what the runner
passes: `host, user, passwd`, then the command, commands, payload or rollback number, then
`session_timeout, command_timeout` (and `commit_confirmed` for an edit), with `port=` and
`vendor_hint=` as keywords; `dry_run=` and `expected_diff=` on `edit` for a driver that declares
`dry_run`, `comment=` on `edit`, `confirm` and `rollback` for `comment`, and `rpc_batch()` next to
`rpc()`. A capability declared and not backed would otherwise fail on the first device with a
`TypeError` where a refusal should have been. Run it with the package installed; for one that is not,
build the entry point in a test and hand it to `drivers.load([...])`, as `tests/test_entry_points.py`
does with the packages under `tests/fixtures/`.

## Defaults

Typing `--user` on every run gets old. `~/.h-ssh/config` holds per-user defaults:

```ini
# ~/.h-ssh/config
user      = EF
workers   = 16
retries   = 0
session_timeout = 5
command_timeout = 15
transport = openssh
```

Precedence is flag → config file → built-in default. A value given on the command line always wins;
only the credentials have an environment step: `--user` falls back to `HSSH_USER`, then the file's
`user`, then the name you are logged in as, like ssh; the password has no flag and no file entry:
`HSSH_PASSWORD` when set, else the prompt.

`transport` is the vendor for targets that don't declare one — `name,ip` inventory rows, a target
without one (`10.0.1.1`, `R1:10.0.1.1`), or a job entry without a vendor. The example above runs those through the
system `ssh` binary; a vendor on the target itself always wins.

`session_timeout` is the one worth setting. It defaults to 30s, which is how long every unreachable
device costs you; on a LAN a reachable device connects in well under a second.

**Passwords are never read from this file.** A config file on a shared jump host is the wrong place
for a secret; a `password`, `passwd`, `secret`, `token` or `pass` line is refused with exit 2 naming
it, exactly as in a run file. Use the prompt or keys, and `HSSH_PASSWORD` for a pipeline.
`--config PATH` points at a different file, and that path must exist: a typo is exit 2, only the
default path may be absent. Every line is `key = value`; a line that is not is exit 2 naming it, as
is a value outside the flag's range (`workers` 1..256, `session_timeout` and `command_timeout`
1..86400, `retries` 0 or more). The flags are held to the same ranges, and a usage error prints one
line, not the usage block.

## Run files

A pipeline step does not want fifteen flags, and neither does a jump host at three in the morning.
A run file is the whole run in one YAML (or JSON) file:

```yaml
# fleet-bgp.yaml
devices: inventories/ax.csv        # a CSV path, or an inline list (below)
transport: junos
user: h-lab                        # never a password: see below
workers: 64
retries: 1
session-timeout: 15
format: xml
commands:                          # a batch, one session per device
  - show bgp summary
  - show route summary
log: runs/bgp.jsonl
audit-log: audit.jsonl
```

```bash
h-ssh --run fleet-bgp.yaml                 # on the jump host: asks for the password once
HSSH_PASSWORD=... h-ssh --run fleet-bgp.yaml --json > out.json   # in a pipeline: no terminal needed
h-ssh --run fleet-bgp.yaml --dry-run       # a flag on the command line wins over the file
```

Every key is a flag name, written with `-` or `_`, and gets the flag's validation: a transport outside
the list, `workers: 0`, `format: csv` or an unknown key is exit 2 naming the key. Precedence is
command line → run file → environment → `~/.h-ssh/config` → built-in default, so a `--dry-run` from a
pipeline variable overrides whatever the file says. Relative paths in the file (`devices`, `batch`,
`edit-dir`, `edit-broadcast`, `log`, `audit-log`, `save-output`, `safety-file`) resolve against the
file's own directory, so a run directory with its inventory and set files moves as one.

Three keys have no flag of their own:

```yaml
devices:                           # inline targets instead of a CSV
  - R1:10.0.1.1:junos
  - {name: R2, host: 10.0.1.2, vendor: junos, port: 830}
commands: [show version, show route summary]      # an inline --batch
jobs:                              # the entries a --job file holds
  - {target: "R1:10.0.1.1:junos", show: show bgp summary}
  - {target: "R3:10.0.1.3:junos", edit: set system host-name R3-new}
```

The rest are the flags: `show`, `edit`, `edit-dir`, `edit-broadcast`, `batch`, `rollback`,
`commit-status`, `comment`, `show-diff`, `dry-run`, `commit-confirmed`, `yes` (or `assume-yes`:
YAML reads a bare `yes:` as a boolean, both spellings work), `structured`, `format`, `json`, `raw`,
`diff`, `verbose`, `save-output`, `log`, `audit-log`, `safety-file`, `retries`, `workers`,
`session-timeout`, `command-timeout`, `transport`, `user`.

Two rules the file cannot bend:

- **No credential, ever.** `password`, `passwd`, `secret` and `token` keys are refused before anything
  runs. The password comes from `HSSH_PASSWORD` or the prompt when stdin is a terminal, exactly as
  without a file, so a run file can live in git or on a shared jump host.
- **Changes need a timer.** A run file that commits (`edit`, `edit-dir`, `edit-broadcast`, `rollback`,
  or a job with an edit) must set `commit-confirmed` in the file or on the command line, or be a
  `dry-run`; otherwise exit 2. Nobody watches a pipeline, and an unattended commit without a rollback
  timer is the one thing it must not be able to do by accident. The `y/N` question and `-y` work as
  they do for flags, and the banner names the file, the device count and the timer.

The file is declarative: no variables, loops or templating. A pipeline that needs them generates the
file. YAML needs PyYAML, which comes along with junos-eznc, so every install has it; a JSON run file needs nothing.

## Output

| Flag | Prints |
|---|---|
| *(none)* | one status line per device, plus the verdict and diff under it for edits |
| `-v` | status plus a framed block per device |
| `--raw` | device output only: no banner, progress lines or summary on stdout |
| `--json` | one object per device: `device`, `host`, `vendor`, `ok`, `duration_ms`, then `command` and `output` for a show, a `commands` list (one entry per command) for `--batch`, `output` alone for an edit, `error` for a failure; with `--diff` the objects come in target order and each device that answered has a `diff` against the baseline (`(baseline)` on the baseline itself) |
| `--format json\|xml` | the router's own JSON or XML reply instead of CLI text (Junos only; every other transport refuses it, nothing sent): pretty-printed wherever output is printed; in `--json`, `output` carries the JSON as data and the XML as a string |

A reader that stops early (`h-ssh ... | head`) is not an error: the run ends quietly with exit 0 and
no traceback, and whatever had landed stands. paramiko's transport thread logs a full traceback when
a device closes the connection mid-handshake; the CLI keeps that off the screen (the one FAIL line
already says so) unless `-v` is given. A library caller configures logging as it likes.

`--raw` is the pipe-friendly one: no banner, no progress lines, no summary. Each device gets a
`name:` line and its output; failures and the verdict go to stderr, so for a show `--raw > out.txt`
keeps the file clean even on a partial run. Two things still print to stdout: the `Resolved 'ver' ->
'show version'` line a shortcut produces, and an edit's pre-flight check and confirmation.

```console
$ h-ssh -sC "show version | match Junos:" --raw
cr1:
Junos: 24.2R1-S2.5

cr2:
Junos: 24.2R1-S2.5
```

`--raw` is exclusive with `-v` and with `--json`; asking for either pair is an error rather than a
silent preference (`--json -v` is accepted: the JSON is printed and `-v` does nothing). The command echo (`$ show version`) belongs to the framed view — `--raw` and `--json`
both drop it, and `--json` reports it as its own `command` field instead of repeating it inside
`output`.

### The result store

Every run is kept. The store is `h-ssh.db` in the directory you run from, so the evidence sits with
the job (`cd customer-x && h-ssh ...`); `--store PATH`, `HSSH_STORE=PATH` or `store = PATH` in
`~/.h-ssh/config` name another file, in that order of precedence, and `--no-store` keeps nothing of
one run. One SQLite file, run after run: one row per command per device — run, device, host, driver,
the command as sent, when, OK or not, the duration, the error, the format (`text`, `xml`, `json`) and
the device's own reply. A show
is one row, a `--batch` one row per command in order, an edit one row with the payload as the command
and the verdict (the diff, the commit line) as the output, `--commit-status` the history as JSON. A
second table, `runs`, has one row per invocation: when it started and finished, the mode, what it was
about, the whole command line, who ran it and from where, and the counts. Everything is kept as it
came: a snapshot one may have to restore from is not edited, so nothing in the store is redacted, and
a `show configuration` keeps its hashes. The file is created 0600, opened and its tables made before
the first device: a store that cannot be written is no run (exit 2, nothing sent), because a run
nobody can look up afterwards is not worth having. A store that fails during the run (the disk
fills, someone deletes or replaces the file) does not stop the devices' replies from being shown; the
loss is said as it happens, counted at the end with its reason, and the run exits 4. A file
overwritten in place (same inode) is the one case that goes unnoticed.

Writes are one transaction per device result, in WAL mode with `synchronous=NORMAL`: a row costs
about a tenth of a millisecond, a 250-device run adds a few tens of milliseconds, the file never
corrupts and every commit survives the process dying; only a power cut can lose the last commits.
Two h-ssh runs may write one store at the same time, including two that create it at the same
instant; a writer waits up to ten seconds for the other's commit before it gives up.

The store holds output and nothing else: no parsing, no normalising, no per-command schema — what is
done with the replies is the reader's business. `h-ssh-store` is the reader that ships; it looks where
the run wrote (`--store PATH`, `HSSH_STORE`, the config file's `store`, else `./h-ssh.db`):

| Command | Prints |
|---|---|
| `runs [--last N]` | the runs, newest first: id, start, mode, user, targets/ok/fail, what it was about |
| `failed [RUN]` | the failed rows of a run (default: the last), with the device's error line; exit 1 when there are any |
| `output DEVICE [RUN] [--seq N]` | one reply, as the device gave it; the error on stderr and exit 1 for a failed row |
| `grep PATTERN [--run] [--device] [--command] [-i]` | the lines of stored replies that match a regex, with run, device and command |
| `field PATH [--run] [--device] [--command]` | a dotted path into JSON replies (`--format json` shows, commit histories): the device's structure read, not parsed |
| `diff DEVICE RUN_A RUN_B [--seq N]` | one device's reply in two runs as a unified diff; exit 1 when they differ (lines are compared without their line endings) |
| `history DEVICE [--command C] [--last N]` | every stored result for a device, newest first |
| `slowest [RUN] [--last N]` | the slowest results, of a run or overall |
| `export [RUN] [--all] [--device D] [--command C] [--format csv\|jsonl] [--out FILE]` | the rows as they are, for a spreadsheet or a notebook: CSV (a multi-line reply is one quoted cell) or JSON Lines; one run (default: the last) or the whole store. The file itself is plain SQLite, so `pandas.read_sql("SELECT * FROM results", sqlite3.connect("h-ssh.db"))` works as well |

A run is named by its id or any unique prefix of it (`20261024-1730` when only one run started then).
Anything else is a `sqlite3 runs.db` query away: the schema is two tables, documented at the top of
`hssh/store.py`.

```console
$ h-ssh --devices core.csv -sC "show bgp summary"
$ h-ssh-store runs
run                   started              mode  user   targets/ok/fail  command
20261024-173057-e45e  2026-10-24T17:30:57  show  h-lab  10/10/0          show bgp summary
$ h-ssh-store diff cr1 20261024-1730 20261023-0905
```

## Failure handling

A device that black-holes packets used to cost the full timeout three times over. Failures are now
classified before anything is retried:

| Failure | Behaviour |
|---|---|
| Unreachable — timed out, refused, no route, network unreachable | fail immediately on `junos` and `openssh`; on `ssh` and `telnet*` a connect timeout or an unresolvable name is still retried (the socket's bare `timed out` / `Name or service not known` matches no marker) |
| Authentication, host key, rejected command (and an unresolvable name on `junos`/`openssh`) | fail immediately |
| The request itself is wrong — `--structured` on a command without a binding, no password and no key to offer (`ssh`), a user or host name OpenSSH refuses, a `known_hosts` line that cannot be parsed, a host PyEZ does not accept | fail immediately: the same call cannot come out differently |
| Failures *after* connecting — command timeout, reset, broken pipe | retried, `--retries` times (default 2) |

The split is whether a connection was established. A connect-phase failure has already spent the
full `ConnectTimeout`; spending it twice more is what lets one dead device dominate a fleet run.
Unreachable means unreachable for the duration of the run on the transports that report it as such
(`junos`, `openssh`); `ssh` and `telnet*` still spend `--retries` extra connect timeouts on a dead
or unresolvable host. Once a session exists, a read failure may well be transient, so those still get retried. **Edits are different:** a config push is retried only when
the driver reports that nothing reached the device (for Junos: a candidate-lock failure, over NETCONF
or a refused `configure exclusive`; a connect failure is unreachable like any other and stops at one).
Any other failure — above all a timeout around a commit — is reported once and left for you to check.

Retrying an authentication failure cannot succeed either, and on a fleet it spends three real login
attempts per device against accounts that may lock out. Those stop at one.

One unreachable device in a three-device lab run, at default settings: **28s** before, **8s** now —
a single timeout rather than three plus backoff.

`--workers` defaults to 8; when the fleet is more than four waves of workers the banner says so with a hint (`Hint: 250 devices at 8 workers is 32 waves; --workers 64 would be 4`), since the workers spread over routers and each router still sees one session. It is honoured literally, up to 256, within the open-file limit: an in-flight NETCONF session costs about six descriptors, so the soft limit (`ulimit -n`) is raised towards the hard one when it is short, which needs no privilege, and only what is still short lowers the workers, with one warning naming the limit and the number run. The vendor calls block, so each in-flight device holds
a thread; h-ssh sizes the executor to `--workers` rather than leaving it at asyncio's default of
`min(32, cpu+4)`, which on a 2-vCPU jump host is **6 threads no matter what you asked for** — and a
device stuck in a 30s connect timeout holds one of those six the whole time.

Ctrl-C stops starting new devices and lets the calls already in flight run out: a commit that was on
its way to a router is reported, logged and audited like any other, never dropped. The run then
reports how many devices completed (`Interrupted. Completed 1 of 3 device(s).`, on stderr) and exits
`130`. Output already written to stdout stays valid, so a truncated `--raw` run cannot look like a
complete one. A device that was still being connected to when Ctrl-C came, and whose connect then
ran out on its own, is reported as `INTERRUPTED` rather than `FAIL`: nothing reached it and the
operator stopped the run. Its entry carries `interrupted: true`, its error starts with `interrupted
while connecting:`, the notice says `; N interrupted while connecting`, and the summary gains an
`interrupted` count. With `--json` there is no notice: the array holds only the devices that completed, the
summary's `targets` is that count, and the exit code is still `130`.

## Safety

Layered. The automatic layers — pre-flight, confirmation, syntax guard — only run for a write; the opt-in
ones (`--safety-file`, `--audit-log`, `--log`) apply to every mode once given.

| Guard | Flag | Behaviour |
|---|---|---|
| Pre-flight check | *(automatic)* | Edits verify reachability before touching config: a TCP connect plus, for `junos`/`ssh`/`openssh`, the SSH banner, so a port that merely accepts and closes is not a device. Probed `--workers` at a time with `--session-timeout` each, like the run itself, and a probe that fails is tried once more before the device is called unreachable: 250 probes at once trip sshd's `MaxStartups` and a router's `ssh rate-limit`, and called devices unreachable that the real 32-worker edit then reached. Skipped under `--show-diff`, whose previews prove it |
| Confirmation | *(automatic)* | Edits prompt `y/N`; `-y` to skip in automation |
| Dry run | `--dry-run` | Junos over NETCONF: loads, diffs, runs `commit_check` (when there is a diff), then discards the candidate. `telnet-junos`: `configure exclusive`, loads, `show \| compare`, `rollback 0` — no commit check, so the diff is shown but not validated. Other transports **refuse** `--dry-run` for edits instead of pretending |
| Show diff, then ask | `--show-diff` | Edits: dry-run on every target, every diff printed, one `y/N` (a TTY, or `-y`) before anything is committed; a preview that fails on any device ends the run (exit 1) with nothing committed. Each commit is then checked against the diff it showed: a device (or a config file) that changed in between is refused with `diff changed since preview; nothing committed` |
| Commit comment | `--comment TEXT` | Logged with the commit (`show system commit`, the audit log), so a change can be found again on the box. NETCONF `junos` only: `telnet-junos` and every other transport refuse it rather than drop it, and it needs an edit (`-eC`, `-eD`, `-eB`, `--rollback`, or a job with edits) |
| Commit confirmed | `--commit-confirmed [N]` | Junos rolls back after N minutes (10 when N is omitted) unless confirmed (confirm with `-eC "commit"`; a run without `--json` ends by printing that command for its own targets, a `--job`'s edit entries included). Transports that cannot do this (`ssh`, `arista`, telnet IOS/NX-OS/Arista, `openssh`) refuse it rather than commit with no timer |
| Reply verdict (`ssh`, `openssh`) | *(automatic)* | A show whose reply opens with `error: ...` (Junos) or `% ...` (IOS, EOS) is FAILED as refused, not reported as output; an edit line the device answers with `error: ...` (Junos) or `% ...` (IOS, Arista) is FAILED with that line even when the command exits 0, and the edit stops there; a show is output whatever it says |
| Junos syntax guard | *(automatic)* | Enforces set-style syntax — each line must start with `set`, `delete`, `activate`, `deactivate`, `insert`, `rename`, `copy`, `annotate`, `protect` or `unprotect`, lowercase — with `#`-only comments, for `junos` and `telnet-junos` (checked when any target is one). `commit` (or `commit;`) is only valid as the single, exact command in `-eC` or a `--job` edit, never inside `-eD`/`-eB` configuration files |
| Safety gate | `--safety-file PATH` (or `HSSH_SAFETY_FILE`) | Opt-in. Sliding-window rate limit (10 attempts / host / 60 s, counted within one run) and a 120 s cooldown after any failure against the device — connect, auth, a timed-out or rejected command, a failed commit — held in a `flock`'d 0600 JSON file so the cooldown persists across processes. Fails closed and preserves corrupt files as `.corrupt` without silent overwrite. The file and its `.lock` are created and locked once before the first device; a path that cannot be created, opened or locked (a missing directory, a symlink, a FIFO) refuses the run with exit 2 |
| Audit trail | `--audit-log PATH` (or `HSSH_AUDIT_LOG`) | Appended as 0600 JSONL with secret redaction (`encrypted-password`, `secret`, `password`/`passwd`, `authentication-key`, `md5-key`, `community`, `pre-shared-key`, `ascii-text`, hex keys, API tokens). One entry per device for every mode — shows included, without their output — plus pre-flight aborts and user cancellations; records diffs for edits. The file is opened once before the first device, so an unwritable path refuses the run before anything is sent (exit 2); in edit modes, audit write failures during the run fail it |
| Run log | `--log PATH` | Per-device results of the run (command, output or error, duration) as JSONL, one line as each device finishes, appended with the same 0600 mode and secret redaction as the audit trail, and probed before the first device like the audit log |
| Result store | *(always on)* `./h-ssh.db`; `--store PATH`, `HSSH_STORE`, `store =` in the config; `--no-store` | Every command's reply in one SQLite file, as the device gave it, one row per command per device plus a row per run; 0600, nothing redacted (it is a snapshot to restore from); opened before the first device, so a store that cannot be written is no run (exit 2). Read with `h-ssh-store` (see [The result store](#the-result-store)) |

A request h-ssh refuses before touching the device (bad arguments, a missing config file, `--dry-run` or `--commit-confirmed` on a transport that cannot honour it) does not start a cooldown; only failures against the device do.

The gate is deliberately fail-closed: a device is marked active *before* the attempt, so a second attempt on the same host while one is in flight is refused rather than doubled up, and a failure cools it before anything else can try. The mark lives in memory; only cooldowns reach the file, so a crashed process blocks nothing in the next run.

Exit codes: `0` success (also when the operator answers N) · `1` a device failed (also a failed `--show-diff` preview, or an audit write failure in an edit mode) · `2` usage error, a transport that cannot honour the request, or a pre-flight that found a device unreachable · `3` nothing failed but the safety gate skipped a device, so not everything ran (the verdict line says how many) · `4` the store could not keep some or all of the results (a disk that filled, a file deleted or replaced under the run): the replies were shown, a `WARNING` says how many of how many were not kept and why, the summary carries `not_kept`, and the run's record is incomplete; `4` wins over `1` and `3`, the summary's `fail` still says what failed · `130` interrupted. A run that reaches its devices also prints a structured summary to stderr (a usage error, a failed pre-flight or an N at the prompt exit before it):

```
[h-ssh] {"targets": 3, "ok": 2, "fail": 1, "skipped": 0, "elapsed_ms": 812, "mode": "show"}
```

`targets` is the number of devices that completed, `skipped` the safety-gate blocks, `mode` one of `show`,
`edit`, `rollback`, `commit`, `batch`, `job`.

## Structured output

`--structured` returns parsed data instead of text where the vendor can provide it. The fallback is per transport, not per command: `ssh`, `openssh` and `telnet*` have no `show_structured`, so they return text as usual; on `junos` a shortcut without a `structured` binding (or a typed command) fails for that device. There is no capability list to maintain — a vendor module either implements `show_structured` or it doesn't, and that absence *is* the fallback signal.

```bash
./h-app/h-ssh.py --user admin -sC bgp --structured --json --target R1:10.0.1.1:junos
```

| Vendor | Mechanism | Notes |
|---|---|---|
| `junos` | PyEZ Table/View over NETCONF | A **different** request: the binding names an RPC, so this is not a parse of the CLI output |
| `ssh`, `openssh`, `telnet` | — | No bindings; always text |

Bindings live in the same `h-app/hssh/dialects/{dialect}.json` entry as the command, under an optional `structured` key:

```json
"bgp": {
  "command": "show bgp summary | no-more",
  "description": "BGP neighbor summary with session states",
  "structured": {
    "rpc":  "get-bgp-neighbor-information",
    "item": "bgp-peer",
    "key":  "peer-address",
    "fields": {
      "remote_as": {"peer-as": "int"},
      "is_up":     {"peer-state": "True=Established"}
    }
  }
}
```

Output is **vendor-shaped, not normalised** — `bgp` returns the binding's fields (`remote_as`, `is_up`, …) keyed by peer address on a router. Nothing here promises two vendors match, which is why there's no cross-vendor schema to keep in sync. Add bindings one command at a time; without `--structured`, commands without one keep working exactly as before — with it, a junos command without a binding is an error, not text.

`--format json` (or `xml`) needs no binding at all: the router is asked for its RPC translation of the
CLI command (what `| display xml rpc` does) and the reply comes back as the router produces it — the
whole document, in Junos's own JSON or XML. It works for `-sC`, `--batch` (one session per device; per
command a translation round trip plus the RPC) and the show entries of a `--job`, on the NETCONF
`junos` transport; any other transport refuses it rather than handing back text. With an edit,
`--rollback`, `--commit-status` or a job without a show entry it is a usage error (exit 2); the edit
entries of a job and `--dry-run` keep their text. `--structured` stays the fixed-fields path — the
binding names the RPC and the few fields to keep — and the two cannot be combined. `--diff` with
`--format json` compares the pretty-printed text.

```bash
./h-app/h-ssh.py --user admin -sC "show chassis hardware" --format json --json --target R1:10.0.1.1:junos
```

## Library usage

The fleet from a script, with no thread in sight:

```python
import json
from hssh import Fleet

with Fleet(["10.0.1.1", "10.0.1.2", "cr3:10.0.1.3:junos"], transport="junos", user="admin") as fleet:
    for r in fleet.show("show bgp summary"):            # results as the devices finish
        print(r.device, "OK" if r.ok else r.error, f"{r.duration_ms} ms")
        if r.ok:
            print(r.output)                              # the reply, as the device gave it

    res = fleet.batch(["show version", "show route summary"])      # both commands on one session per device
    for r in res:
        for c in r.commands:                             # {"command", "ok", "output"} or {"command", "ok", "error"}
            print(r.device, c["command"], c.get("output", c.get("error")))
    print(json.dumps(res.to_dicts()))                   # every device as data, once the last is in

    hw = {r.device: r.output for r in fleet.show("show chassis hardware", fmt="json") if r.ok}   # the router's own data

    # from asyncio code, the same run:  async for r in fleet.show_async("show version"): ...
```

`Fleet(targets, transport="ssh", user=None, passwd=None, workers=32, session_timeout=30, command_timeout=60,
retries=2, store=None)` takes targets as the CLI does: bare hosts (a device named after its host, on
`transport`), `name:host[:vendor][:port]`, `Target` objects, a `pathlib.Path` to a CSV inventory, or one
string (an existing file is the inventory; a string that reads as a path, with a separator or a
`.csv`/`.yaml`/`.yml`/`.json` suffix, but is not there is refused, so a mistyped inventory path never
becomes a device; anything else is one target); a name or host listed twice is refused before anything
runs. `user=None` is the name you are logged in as; `passwd=None` means keys or an agent, and an empty
string is refused, since the transports do not agree on what it means. The timeouts are whole seconds and
`retries` the attempts after the first, with the CLI's defaults (`--retries 2`): one engine, one behaviour.
The library reads no environment variable and no config file; that is the CLI's job. What it does for you:

- threads talk to the devices, `workers` at a time, lowered to what the open-file limit carries (the process's
  soft `RLIMIT_NOFILE` is raised towards the hard one first, as the CLI does; a `RuntimeWarning` says when
  fewer run); you iterate on your own thread and get one `DeviceResult` per device in the order they finish:
  `device`, `host`, `vendor`, `ok`, `output`, `error`, `duration_ms`, `ts`, `command`, and for a batch
  `commands` (one entry per command, in the batch's order); `result` is the driver's typed answer and `text`
  the runner's full report;
- a failure is a value (`ok` False, the failure in one line in `error`), never an exception out of the loop,
  and the other devices still run;
- every device gets the runner's run: `session_timeout` and `command_timeout`, `retries` with the same
  classification (a failure the same call cannot fix — unreachable, refused, authentication — is tried once;
  a command that is not a read is sent once). A transport call that has not returned within those bounds
  (the SSH and telnet transports may spend up to three session timeouts on the set-up, since connect, banner
  and authentication each get one; NETCONF has one deadline for all of it) plus 10 s is reported as that
  device's failure and its thread left to finish on its own, so one wedged device cannot hold the run. It
  does hold one worker until it returns: when every worker is held, the devices still queued are failed at
  once rather than waited for, and a later run on the same Fleet fails that device at once (`the previous
  call to this device has not returned`) instead of queueing another call behind it. The worker threads are
  daemon threads, so a call that never returns keeps its thread and never the interpreter's exit;
- one run at a time: a second `show()` or `batch()` while devices of the previous run are still in flight
  raises `RuntimeError` (two runs would queue on the pool's per-router locks, and the time bound would then
  fail honest devices); a previous run whose devices have all returned is wrapped up first and stays readable;
- one session per device, pooled for the Fleet's lifetime however many commands you run. The pool is
  process-wide: the last Fleet to close turns it off only if a Fleet turned it on; a pool you enabled
  yourself is used and left on;
- `close(wait=0)`, or leaving the `with` block, promises this much: devices not yet started are not started;
  the devices a worker is talking to get `wait` seconds to answer (a Ctrl-C handler may pass a few), and what
  returned by then is a result and a store row; the run is recorded as interrupted with the rest as skipped;
  iterating its results afterwards gives what was done by then and nothing more (a call that returns later is
  dropped, its row says skipped), so the store and the script agree; a script waiting in its `for` loop wakes at
  once, whichever thread called `close()`. A store this Fleet opened is closed, and
  the sessions close (one still in use closes when its call returns). `async with Fleet(...)` and `aclose()`
  do the same off the event loop;
- `store=`, a path or an open `hssh.store.Store`, keeps every result as the CLI's store does (one run row, its
  command line `Fleet.show show bgp summary`; one result row per device, per command for a batch), written
  from the thread that iterates and, under `async for`, from a worker of the event loop, so SQLite never
  blocks it; `show_async()` and `batch_async()` are async generators (`async for r in fleet.show_async(cmd)`)
  that start the run on their first step. What the store could not keep is counted, never raised: a write
  that fails is said once as a `RuntimeWarning` and the run goes on; at the end `res.not_kept` says how many
  results were not kept and `res.store_error` why (a store file deleted or replaced under the run means every
  result of it, and its run row is left open, as the CLI does);
- `fmt="json"` or `"xml"` asks for the router's own data through its RPC translation (NETCONF only; on another
  transport that is the device's failure, nothing sent); `to_dicts()` is JSON-serialisable, in the shape of
  the CLI's `--json` records.

Reads only, `show` and `batch`; the command is sent as typed (shortcuts are the CLI's). Edits keep their gates
in the CLI (the set-syntax guard, the pre-flight check, the question) and in the transports' own
`edit()`/`begin()` below.

### One device, one call

```python
from hssh import SafetyGate, Target
from hssh.runner import run_for_target
from hssh.transports import netconf, ssh

# straight at a transport: netconf speaks Junos; ssh and openssh speak the dialect the vendor_hint names
output = netconf.show("10.0.1.1", "admin", None, "show version", 30, 20)
output = ssh.show("10.0.2.1", "admin", None, "show version", 30, 20, vendor_hint="ios@ssh")

# or through the runner, with the safety gate in place — none is applied unless you pass one
target = Target(name="R1", host="10.0.1.1", vendor="junos")
name, ok, output, ms = run_for_target(
    t=target, transport="junos", mode="show",      # the driver comes from Target.vendor
    show_cmd="show version", edit_cmd=None,
    config_dir=None, broadcast_file=None,
    user="admin", passwd=None,
    session_timeout=30, command_timeout=20,
    dry_run=False, commit_confirmed=None, save_dir=None,
    safety_gate=SafetyGate(),   # in memory: 10 attempts per device per 60 s, 120 s cooldown after a failure;
)                               # SafetyGate(safety_file="...") shares the cooldowns across processes
```

`run_for_target` returns a `RunResult`: it unpacks as the four values above, and carries the driver's
typed answer in `.result` (an `EditResult` with `status`, `diff`, `minutes`; a `BatchResult`; a
`CommitStatus` with `.pending`; a show's text or data) and a failure in `.error`. The edit, batch and
commit-status types are also still the text or list the drivers always returned (`hssh/drivers/results.py`).

Connection and command timeouts are separate knobs — a slow login and a slow `show route extensive` are different problems.

### Transactions, comments, commit status

A maintenance wants to look at the diff *before* deciding, keep the candidate on the same session, and
find its commits again on the box afterwards:

```python
with netconf.begin(host, user, None, payload, 30, 20) as tx:         # lock, load, diff, commit check
    print(tx.diff)                                                   # tx.show()/tx.rpc() still work here
    if gate_says_yes(tx.diff):
        tx.commit(confirmed=10, comment="C1 cutover")                 # or tx.abort(); leaving the block aborts

netconf.confirm(host, user, None, 30, 20, comment="C1 cutover (confirmed)")
netconf.commit_status(host, user, None, 30, 20)
# [{'seq': 0, 'user': 'h-lab', 'client': 'netconf', 'time': '…', 'epoch': 1792…, 'comment': 'C1 cutover',
#   'note': 'commit confirmed, rollback in 10mins', 'pending_rollback_minutes': 10}, …]

netconf.guarded_commit(host, user, None, payload, 30, 20, minutes=10,
                       check=lambda: checks_pass(), comment="C1 cutover")
# commit confirmed → check() → confirm, or an immediate `rollback 1` commit; returns what happened:
# {'final': 'confirmed' | 'rolled back' | 'not confirmed' | 'not rolled back' | 'no changes', …}
```

`edit()`, `rollback()` and `confirm()` take `comment=` too; the device's own "rollback in N min" is what
`pending_rollback_minutes` reports, on the latest commit only: once confirmed, a commit keeps that note in
the history (`note`) but is no longer waiting. `confirm()` commits under the configuration lock, so someone else's
uncommitted edits refuse it (`NotAppliedError`, nothing sent) rather than going in with the confirmation.
`guarded_commit()` reads `show system commit` after its commit and again before it confirms or rolls back:
when the pending commit is no longer the one it made — another commit landed, which also confirmed it, or
the checks outlasted the timer and the device rolled back by itself — it sends nothing and answers
`not confirmed` / `not rolled back` with the reason, the history under `status` and, when the checks
failed, their error under `check_error`, because a `rollback 1` at that point would re-apply the change
that just failed its checks. A session with an open transaction stays borrowed —
other threads wait for it, the thread holding it may keep using it, and only that thread can commit or
abort it: a `Transaction` finished from another thread (an `asyncio.to_thread` that landed elsewhere) is
refused before anything is sent, because the session's lock belongs to the thread that opened it.

### Structured output from a script

`show()` returns the CLI text. For data, ask for the RPC reply instead — the router translates the CLI
command you know into its RPC (what `| display xml rpc` does), and answers in its own JSON:

```python
hw = netconf.rpc("10.0.1.1", "admin", None, "show chassis hardware", 30, 20)
# -> {'chassis-inventory': [{'chassis': [{'serial-number': [{'data': 'VM6AD25B940C'}], ...}]}]}

netconf.rpc(host, user, None, "get-interface-information", 30, 20,
            args={"interface-name": "ge-0/0/0", "terse": True})   # RPC name + arguments
netconf.rpc(host, user, None, "show route summary", 30, 20, fmt="xml")   # the reply XML, as text
```

`rpc()` runs on the pooled session like everything else, and `rpc_batch()` answers a list of
commands on one session the way `show_batch()` does. `show_structured()` — a PyEZ Table/View
binding that returns a fixed, named set of fields — stays as the fallback for when you want a few
fields keyed by item rather than the whole reply.

### Connection pooling

Every call above opens its own NETCONF session and closes it — right for a one-shot CLI run, wasteful
for a script that goes back to the same router twenty times. Enable the session pool once and every
Junos call reuses the router's open session:

```python
from hssh import pool
from hssh.transports import netconf
pool.enable()                     # sessions idle 300 s are closed (reaper runs once a minute); pool.enable(idle_timeout=60) or HSSH_POOL_IDLE_TIMEOUT=60 to change

for cmd in ("show version", "show bgp summary", "show route summary"):
    netconf.show("10.0.1.1", "admin", None, cmd, 30, 20)   # one NETCONF session, three RPCs

print(pool.POOL.stats)            # {'opens': 1, 'reuses': 2, 'discards': 0, 'reaped': 0}
pool.close_all()                  # also runs at interpreter exit
```

One session per `(host, port, user, credential)` — a digest of the password is part of the key, so a
call with a different or wrong password never rides a session another credential opened. Calls against
the same router from several threads queue on that session; different routers run in parallel as before. A session is dropped, never handed to
the next caller, when something left it in doubt: a commit whose outcome is unknown, a rollback or
unlock that failed, an RPC timeout, or the router closing it. A read (`show`, `show_structured`,
`show_batch`, and `rpc`/`rpc_batch` for a `show …` command or `get-*` RPC) that finds its reused
session dead opens a new one and runs once more; any other RPC (`request-*`, …) and an edit never do —
an edit reports `NotAppliedError` if the session died before the lock, and the usual verdicts after. The CLI enables the pool for a `--job` run only, so a job that lists one device in several entries logs in once per device and runs its entries on that session, in file order; every session is closed when the run ends, on Ctrl-C too. `-sC`, `--batch` and the edit modes still open one session per device per run. While a session is open it holds four descriptors (its socket, paramiko's pipe pair, ncclient's epoll), so size `ulimit -n` for the sessions you keep; what a closed session leaves to the garbage collector is collected when `close_all()` or the reaper closes anything. A pooled session idle for more than 30 s is asked whether it is still there before it is reused; a refusal from the router (cRPD has no uptime RPC, a login class may withhold it) keeps the session, since the router answered, and only a transport failure or no answer within 5 s replaces it.

## Package structure

```
h-ssh/
├── h-app/
│   ├── hssh/
│   │   ├── __init__.py      # public API: Target, Fleet, run_for_target, SafetyGate, pool, drivers, transports; __version__
│   │   ├── core.py          # Target, CSV loader, template resolver, job parser
│   │   ├── cli.py           # argument parsing + orchestration
│   │   ├── runner.py        # concurrent execution engine
│   │   ├── fleet.py         # Fleet: show/batch across the fleet from a script, results as values, pooled sessions, the store
│   │   ├── limits.py        # the worker ceiling and the open-file limit the workers must fit under
│   │   ├── pool.py          # opt-in session pool for library use
│   │   ├── safety.py        # SafetyGate — rate limit + cross-process cooldown
│   │   ├── audit.py         # JSONL audit trail
│   │   ├── store.py         # the result store (./h-ssh.db, every run): SQLite writer and the h-ssh-store reader
│   │   ├── errors.py        # NotAppliedError, AmbiguousCommitError — what the retry logic keys on
│   │   ├── dialects/        # what each device speaks, with its shortcut library next to it
│   │   │   ├── base.py      # Dialect, CliSyntax, the default read rule
│   │   │   ├── junos.py     # set-syntax guard, refusal regex, candidate CLI, commit-pending note  + junos.json
│   │   │   ├── ios.py       # IOS-shaped CLI and `% ` refusals; nxos.py, eos.py (+ eos.json) build on it
│   │   │   └── none.py      # no vendor knowledge: error:/% refusals, IOS-shaped prompt  + none.json
│   │   ├── transports/      # how a device is reached: each module does one transport's work for every dialect on it
│   │   │   ├── netconf.py   # PyEZ NETCONF: show, structured, rpc, config transactions, commit-confirmed, commit status
│   │   │   ├── ssh.py       # paramiko: exec channel for shows and none-dialect edits, the CLI engine on a shell for dialect edits
│   │   │   ├── openssh.py   # the OpenSSH binary — zero dependencies; the CLI engine on `ssh -tt` for dialect edits
│   │   │   ├── telnet.py    # the telnet channel (socket + option negotiation), the CLI engine on it in the dialect the name says (frozen)
│   │   │   └── cli.py       # the CLI engine: login, prompt, run, paging, candidate/lines edits, confirm — on any channel
│   │   └── drivers/
│   │       ├── base.py      # Transport, Driver and the capability words
│   │       ├── __init__.py  # the registry: dialect@transport names, today's names as aliases, the `hssh.drivers` entry points
│   │       ├── contract.py  # what a module must offer to back a driver's `supports`
│   │       └── results.py   # EditResult, BatchResult, CommitStatus: typed answers that are still their text/list
│   ├── tests/               # the unit suite; tests/dialects, tests/drivers, tests/transports per layer, tests/fixtures the packages the entry-point tests load
│   ├── h-ssh.py             # CLI entry point
│   ├── devices.csv          # example inventory
│   ├── example_library_usage.py       # library walkthrough
│   └── custom_automation_example.py   # build on hssh: CSV loader + junos driver
├── .github/workflows/tests.yml   # unit suite, Python 3.10–3.13
├── assets/                  # banner, badges
├── TESTS.md                 # what was run on which code
└── pyproject.toml           # installs the `h-ssh` and `h-ssh-store` entry points from h-app/; declares the built-in drivers under `hssh.drivers`
```

## Develop

```bash
pip install -e '.[dev]'
pytest
```

The unit suite (937 tests) needs no devices and runs on every push to `main` or `develop` and on every pull request (GitHub Actions, Python 3.10–3.13, plain
`python` containers, no JavaScript actions). It is laid out by layer where the package is (`tests/dialects`, `tests/drivers`, `tests/transports`), with the
contract test running over every registered driver, entry points included. Beyond it, live runs against Junos vMX routers cover the session pool, the NETCONF
edit paths, the RPC/JSON paths, a full commit-confirmed maintenance flow, the confirm under the lock, and a 29-check release
gate (failure handling, edit safety, one real commit per write feature, the library API on one pooled session); the earlier
59-test run covered every CLI mode, both edit paths, concurrency, error handling, exit codes and the safety gate. What was run
on which code is in [TESTS.md](TESTS.md).

## Related global repos

- [`Juniper/junos-mcp-server`](https://github.com/Juniper/junos-mcp-server): the same device access exposed to an LLM over MCP; h-ssh's session pool is the `ConnectionPool` h-network contributed there
- [`h-network/h-cli`](https://github.com/h-network/h-cli): AI-driven infrastructure management this feeds into
- [`h-network/h-agent`](https://github.com/h-network/h-agent): unattended launcher for claude, codex and agy
- [`h-network/h-mesh`](https://github.com/h-network/h-mesh): agentic office framework

## License

PolyForm Noncommercial 1.0.0 -- see [`LICENSE`](LICENSE). "h-ssh" and "h-network" naming/branding are covered by
[`TRADEMARKS.md`](TRADEMARKS.md).
