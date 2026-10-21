<div align="center">

<img src="assets/banner.svg" alt="H-SSH // the fleet loop, not the session // h-network" width="600">
 
<br/>

[![License: PolyForm Noncommercial 1.0.0](assets/badges/license.svg)](LICENSE)
![Python 3.10+](assets/badges/python.svg)
![Vendors: junos arista ssh openssh telnet](assets/badges/vendors.svg)
![Runtime dependency: paramiko only](assets/badges/deps.svg)

</div>

# h-ssh

`h-ssh` runs commands across a fleet of network devices: one device or three hundred, Juniper, Arista, any SSH host, or a console
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

- **Five transports, one interface.** Juniper (PyEZ over NETCONF), Arista (eAPI), any SSH host through paramiko or the system `ssh` binary, and raw-socket telnet with IOS-, Junos-, Arista- and NX-OS-flavoured prompt handling. Same flags whichever you point it at; the ones only a Junos transport can honour (`--dry-run` on an edit, `--show-diff`, `--commit-confirmed`, and over NETCONF `--comment`, `--format`, `--rollback`, `--commit-status`) are refused on the others before anything is sent, never faked.
- **Parallel by default.** Devices are worked concurrently behind an `asyncio` semaphore, `--workers 8` out of the box. 3 routers, 3 show commands, ~350 ms end to end.
- **One command or many, one device or many.** `--batch` runs several commands per device on a single connection; `--job` takes a JSON file with different commands — and different modes — per device, readable from a file or stdin.
- **Writes are gated.** Pre-flight reachability check, `y/N` confirmation, `--dry-run` that shows the diff without committing and `--commit-confirmed N` for changes that undo themselves unless you confirm within N minutes (both Junos), and an opt-in per-device rate limit and cooldown (`--safety-file`).
- **Templates instead of memorised syntax.** `-sC bgp` resolves through a per-vendor JSON template library — *per target*, so the same shortcut sends a Junos router and an Arista switch each their own command. Drop your own in `~/.h-ssh/commands/{vendor}.json` to override.
- **Built to be scripted.** `--json` on stdout, a structured summary line on stderr, meaningful exit codes, and credentials from `HSSH_USER` / `HSSH_PASSWORD` — or import `hssh` and skip the CLI entirely.
- **Built for a maintenance, not just a run.** A session pool keeps one NETCONF session per router open for a whole script; `rpc()` and `--format json|xml` return the router's own data instead of CLI text; `begin()` holds a diffed candidate open until a gate decides; `--rollback N`, commit comments, `--commit-status` and `guarded_commit()` cover the commit-confirmed lifecycle without a `| match` in sight.
- **One runtime dependency — or none.** `paramiko`. Vendor libraries are optional extras, telnet is a raw socket (no stdlib `telnetlib`, so it still works on Python 3.13+), and the `openssh` transport drives the system `ssh` binary, so a locked-down jump host with nothing installable still runs the whole tool.

## How it works

```
  devices.csv / --target / --job              per device, up to --workers at once
  ──────────────────────────────────           ─────────────────────────────────────
                    │                          ┌─ junos    PyEZ over NETCONF (830)
                    ▼                          │           show/edit → PyEZ NETCONF
        ┌───────────────────────┐              │                  lock → load → diff
        │ safety gate (opt-in)  │              │                  → commit → unlock
        │ rate limit 10/device  │──▶ workers ──┼─ arista   eAPI over HTTPS
        │ cooldown 120s on fail │              ├─ ssh      exec_command
        │ --safety-file, flock'd│              ├─ openssh  the ssh binary, no deps
        └───────────────────────┘              └─ telnet   raw TCP + prompt match
                    │                                          │
                    └──────────── every edit ──────────────────┴──▶ --audit-log (JSONL)
```

On Junos, show commands run through PyEZ `Device.cli()` over one NETCONF session (a batch shares it), and the NETCONF port defaults to 830 for every Junos call; set the target's port to use NETCONF on 22. Config changes lock the candidate, load, diff, run `commit_check`, commit, and unlock, rolling back if any step fails. Confirming a commit-confirmed (`-eC "commit"`) locks too, so another user's uncommitted edits in the shared candidate refuse it — nothing sent, retried like any other lock refusal — instead of riding along with the confirmation. A commit whose reply never arrives is reported as *outcome unknown* and is never retried or rolled back automatically — check the device (and any commit-confirmed timer) first.

## Install

```bash
git clone …/h-ssh.git && cd h-ssh
python3 -m venv .venv && . .venv/bin/activate

pip install -e .                  # core (paramiko) — SSH + telnet
                                  # nothing installable? the openssh transport
                                  # runs straight from the checkout, no deps
pip install -e '.[junos]'         # + junos-eznc (NETCONF config)
pip install -e '.[arista]'        # + pyeapi
pip install -e '.[all]'           # + both
pip install -e '.[dev]'           # + pytest, both vendor libs
```

Requires Python 3.10+. Installs an `h-ssh` entry point; the checkout's `./h-app/h-ssh.py` works uninstalled too.

## Quick start

```bash
# show command across two routers, inline targets
./h-app/h-ssh.py --user admin -sC bgp --target R1:10.0.1.1:junos --target R2:10.0.1.2:junos

# ... or from a CSV inventory, as JSON (the sample inventory has junos, arista and ssh rows: needs `.[all]` and a password)
./h-app/h-ssh.py --user admin --json -sC "show version" --devices h-app/devices.csv

# compare one command's output across the fleet
./h-app/h-ssh.py --user admin -sC bgp --diff --target R1:10.0.1.1:junos --target R2:10.0.1.2:junos

# config change — look before you leap (no --target/--devices: the inventory is ~/.h-ssh/devices.csv, or ./devices.csv)
./h-app/h-ssh.py --user admin -eC "set system ntp server 10.0.0.1" --dry-run
./h-app/h-ssh.py --user admin -eC "set system ntp server 10.0.0.1" -y

# a change that rolls itself back in 10 minutes unless you confirm
./h-app/h-ssh.py --user admin -eB configs/all.set --commit-confirmed 10 -y

# several commands per device, one connection
./h-app/h-ssh.py --user admin --batch commands.txt --target R1:10.0.1.1:junos

# a console server still speaking telnet
./h-app/h-ssh.py --user admin -sC "show version" --target SW1:10.0.0.1:5000:telnet-ios
```

Targets are `NAME:HOST`, `NAME:HOST:VENDOR`, `NAME:HOST:PORT` or `NAME:HOST:PORT:VENDOR` (`NAME:HOST:VENDOR:PORT` works too, and is what the confirm hint prints); an IPv6 host goes in brackets, `R1:[2001:db8::1]:junos`. A CSV inventory accepts `name,ip`, `name,ip,vendor` or `name,ip,vendor,port`, or one bare hostname per line; headers or none, and `#` comments, full-line or trailing.

**A target that doesn't declare a vendor gets `--transport`**, which defaults to plain `ssh` — the transport that assumes least, since its show and edit paths are both `exec_command`. Declare `junos` or `arista` on the target to get NETCONF or eAPI, or set it once with `--transport junos` (or `transport = junos` in `~/.h-ssh/config`) for an inventory of `name,ip` rows; a vendor on the target itself always wins. Command shortcuts resolve per target against that vendor, so one `-sC bgp` across a mixed inventory sends each device its own command.

### Authentication

```bash
./h-app/h-ssh.py --user admin -sC bgp                     # SSH agent / key, or type it at the prompt
export HSSH_USER=admin HSSH_PASSWORD=secret               # or from the environment, nothing to type
```

`--password secret` works too, but a command line is visible to every user on the host (`ps`,
`/proc/<pid>/cmdline`) and ends up in the shell history. On a shared jump host, use the environment
or the prompt. The same goes for the `openssh` transport's commands: each line runs as the `ssh`
process's argument, so a config line is readable from `ps` for the life of that process; push
secrets over NETCONF or paramiko, not over `openssh`.

## Modes

| Flag | Mode | What it does |
|---|---|---|
| `-sC` | Show | Run a show/display command (or a template name). A command that acts on the device (`request …`, `clear …`) is sent once and never retried, and refused under `--format` |
| `-eC` | Edit command | Apply one config line to every target |
| `-eD` | Edit directory | Per-device config from `<NAME>.set` files: blank and full-line `#` comments are skipped, nothing else is touched, so `community ab#12` goes as written |
| `-eB` | Edit broadcast | One config file applied to all targets |
| `--batch` | Batch | Several show commands from a file, one connection per device |
| `--job` | Job | Per-device commands *and* modes from JSON — file or `-` for stdin |
| `--rollback N` | Rollback | Return every target to rollback N (0–49): the same lock → diff → commit check → commit → unlock as an edit, so `--dry-run` shows the diff of going back and `--commit-confirmed` arms the timer (Junos) |
| `--commit-status` | Commit status | `show system commit` as data per target: sequence, time, user, comment, and the pending commit-confirmed timer (Junos) |

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

## Transports

| Vendor | Transport | Library | Show | Edit |
|---|---|---|---|---|
| `junos` | NETCONF | junos-eznc | PyEZ `Device.cli()` | PyEZ lock/load/diff/commit |
| `arista` | eAPI (HTTPS) | pyeapi | eAPI enable | eAPI `configure session` / diff / `commit` |
| `ssh` | SSH | paramiko | `exec_command` | `exec_command` |
| `openssh` | OpenSSH client | built-in | `ssh host cmd` | `ssh host cmd` |
| `telnet` | Raw socket | built-in | raw TCP | config mode |
| `telnet-ios` | Raw socket, IOS prompts | built-in | raw TCP | `configure terminal` |
| `telnet-junos` | Raw socket, Junos prompts | built-in | raw TCP | `configure exclusive` / `commit` |
| `telnet-arista` | Raw socket, EOS prompts | built-in | raw TCP | `configure terminal` |
| `telnet-nxos` | Raw socket, NX-OS prompts | built-in | raw TCP | `configure terminal` |

Every transport runs a batch on one session per device; eAPI is HTTP, so there each command is its own
request on the same node.

Telnet is a prompt match on a raw socket, so it is strict about what it has not seen. A read that reaches
its timeout or loses the connection is an error, never a partial reply passed off as the device's answer,
and a `login:`/`Password:` prompt back after the password is a failed login, reported once — not the
command typed in as a username. A port that prints nothing until Enter — a console-server line left at
a prompt — gets one Enter once the session timeout is up, before silence counts as a failed login.
`telnet-junos` edits enter `configure exclusive`, as the NETCONF driver's lock does: a refused lock is
reported before any `set` line is sent, and `commit` and the dry run's `rollback 0` only ever touch
this session's candidate, never another user's pending changes. A commit whose reply never arrives is
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
(`ControlMaster`), so each command still comes back cleanly separated.

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

### `arista` — eAPI over HTTPS

The switch's certificate is verified against the system CAs. A lab CA goes in
`HSSH_EAPI_CA=/path/ca.pem`; a self-signed switch needs `HSSH_EAPI_VERIFY=no`, an explicit choice
where pyeapi's own default is to verify nothing. `session_timeout` covers the TCP and TLS handshake,
`command_timeout` each request after it.

Edits run in an EOS configure session: the lines load into the session, its diff comes back, and
`commit` makes them live together. A rejected line aborts the session and leaves running-config as
it was; `NO CHANGES` means the session diff was empty and nothing was committed.

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
`user`, then the prompt, which offers your system username so Enter accepts it; the password to
`HSSH_PASSWORD`, then the prompt.

`transport` is the vendor for targets that don't declare one — `name,ip` inventory rows, a bare
`--target R1:10.0.1.1`, or a job entry without a vendor. The example above runs those through the
system `ssh` binary; a vendor on the target itself always wins.

`session_timeout` is the one worth setting. It defaults to 30s, which is how long every unreachable
device costs you; on a LAN a reachable device connects in well under a second.

**Passwords are never read from this file.** A config file on a shared jump host is the wrong place
for a secret; use `HSSH_PASSWORD`, the prompt, or keys (`--password` works, but shows in `ps`).
`--config PATH` points at a different file.

## Output

| Flag | Prints |
|---|---|
| *(none)* | one status line per device, plus the verdict and diff under it for edits |
| `-v` | status plus a framed block per device |
| `--raw` | device output only: no banner, progress lines or summary on stdout |
| `--json` | one object per device: `device`, `host`, `vendor`, `ok`, `duration_ms`, then `command` and `output` for a show, a `commands` list (one entry per command) for `--batch`, `output` alone for an edit, `error` for a failure |
| `--format json\|xml` | the router's own JSON or XML reply instead of CLI text (Junos only; every other transport refuses it, nothing sent): pretty-printed wherever output is printed; in `--json`, `output` carries the JSON as data and the XML as a string |

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

## Failure handling

A device that black-holes packets used to cost the full timeout three times over. Failures are now
classified before anything is retried:

| Failure | Behaviour |
|---|---|
| Unreachable — timed out, refused, no route, network unreachable | fail immediately on `junos` and `openssh`; on `ssh`, `telnet*` and `arista` a connect timeout or an unresolvable name is still retried (the socket's bare `timed out` / `Name or service not known` matches no marker) |
| Authentication, host key, rejected command (and an unresolvable name on `junos`/`openssh`) | fail immediately |
| Failures *after* connecting — command timeout, reset, broken pipe | retried, `--retries` times (default 2) |

The split is whether a connection was established. A connect-phase failure has already spent the
full `ConnectTimeout`; spending it twice more is what lets one dead device dominate a fleet run.
Unreachable means unreachable for the duration of the run on the transports that report it as such
(`junos`, `openssh`); `ssh`, `telnet*` and `arista` still spend `--retries` extra connect timeouts on a dead
or unresolvable host. Once a session exists, a read failure may well be transient, so those still get retried. **Edits are different:** a config push is retried only when
the driver reports that nothing reached the device (for Junos: a candidate-lock failure, over NETCONF
or a refused `configure exclusive`; a connect failure is unreachable like any other and stops at one).
Any other failure — above all a timeout around a commit — is reported once and left for you to check.

Retrying an authentication failure cannot succeed either, and on a fleet it spends three real login
attempts per device against accounts that may lock out. Those stop at one.

One unreachable device in a three-device lab run, at default settings: **28s** before, **8s** now —
a single timeout rather than three plus backoff.

`--workers` is honoured literally, up to 256. The vendor calls block, so each in-flight device holds
a thread; h-ssh sizes the executor to `--workers` rather than leaving it at asyncio's default of
`min(32, cpu+4)`, which on a 2-vCPU jump host is **6 threads no matter what you asked for** — and a
device stuck in a 30s connect timeout holds one of those six the whole time.

Ctrl-C stops starting new devices, lets the calls already in flight run out, reports how many devices
completed (`Interrupted. Completed 1 of 3 device(s).` on stderr) and exits `130`. Output already written
to stdout stays valid; the notice goes to stderr, so a truncated `--raw` run cannot look like a complete
one. With `--json` there is no notice: the array holds only the devices that completed, the summary's
`targets` is that count, and the exit code is still `130`.

## Safety

Layered. The automatic layers — pre-flight, confirmation, syntax guard — only run for a write; the opt-in
ones (`--safety-file`, `--audit-log`, `--log`) apply to every mode once given.

| Guard | Flag | Behaviour |
|---|---|---|
| Pre-flight check | *(automatic)* | Edits verify reachability before touching config: a TCP connect plus, for `junos`/`ssh`/`openssh`, the SSH banner, so a port that merely accepts and closes is not a device. Skipped under `--show-diff`, whose previews prove it |
| Confirmation | *(automatic)* | Edits prompt `y/N`; `-y` to skip in automation |
| Dry run | `--dry-run` | Junos over NETCONF: loads, diffs, runs `commit_check` (when there is a diff), then discards the candidate. `telnet-junos`: `configure exclusive`, loads, `show \| compare`, `rollback 0` — no commit check, so the diff is shown but not validated. Other transports **refuse** `--dry-run` for edits instead of pretending |
| Show diff, then ask | `--show-diff` | Edits: dry-run on every target, every diff printed, one `y/N` (a TTY, or `-y`) before anything is committed; a preview that fails on any device ends the run (exit 1) with nothing committed. Each commit is then checked against the diff it showed: a device (or a config file) that changed in between is refused with `diff changed since preview; nothing committed` |
| Commit comment | `--comment TEXT` | Logged with the commit (`show system commit`, the audit log), so a change can be found again on the box. NETCONF `junos` only: `telnet-junos` and every other transport refuse it rather than drop it, and it needs an edit (`-eC`, `-eD`, `-eB`, `--rollback`, or a job with edits) |
| Commit confirmed | `--commit-confirmed [N]` | Junos rolls back after N minutes (10 when N is omitted) unless confirmed (confirm with `-eC "commit"`; a run without `--json` ends by printing that command for its own targets, a `--job`'s edit entries included). Transports that cannot do this (`ssh`, `arista`, telnet IOS/NX-OS/Arista, `openssh`) refuse it rather than commit with no timer |
| Junos syntax guard | *(automatic)* | Enforces set-style syntax — each line must start with `set`, `delete`, `activate`, `deactivate`, `insert`, `rename`, `copy`, `annotate`, `protect` or `unprotect`, lowercase — with `#`-only comments, for `junos` and `telnet-junos` (checked when any target is one). `commit` (or `commit;`) is only valid as the single, exact command in `-eC` or a `--job` edit, never inside `-eD`/`-eB` configuration files |
| Safety gate | `--safety-file PATH` (or `HSSH_SAFETY_FILE`) | Opt-in. Sliding-window rate limit (10 attempts / host / 60 s, counted within one run) and a 120 s cooldown after any failure against the device — connect, auth, a timed-out or rejected command, a failed commit — held in a `flock`'d 0600 JSON file so the cooldown persists across processes. Fails closed and preserves corrupt files as `.corrupt` without silent overwrite |
| Audit trail | `--audit-log PATH` (or `HSSH_AUDIT_LOG`) | Appended as 0600 JSONL with secret redaction (`encrypted-password`, `secret`, `password`/`passwd`, `authentication-key`, `md5-key`, `community`, `pre-shared-key`, `ascii-text`, hex keys, API tokens). One entry per device for every mode — shows included, without their output — plus pre-flight aborts and user cancellations; records diffs for edits. In edit modes, audit write failures fail the run |
| Run log | `--log PATH` | Per-device results of the run (command, output or error, duration) as JSONL, appended with the same 0600 mode and secret redaction as the audit trail |

A request h-ssh refuses before touching the device (bad arguments, a missing config file, `--dry-run` or `--commit-confirmed` on a transport that cannot honour it) does not start a cooldown; only failures against the device do.

The gate is deliberately fail-closed: a device is marked active *before* the attempt, so a second attempt on the same host while one is in flight is refused rather than doubled up, and a failure cools it before anything else can try. The mark lives in memory; only cooldowns reach the file, so a crashed process blocks nothing in the next run.

Exit codes: `0` success (also when the operator answers N) · `1` a device failed (also a failed `--show-diff` preview, or an audit write failure in an edit mode) · `2` usage error, a transport that cannot honour the request, or a pre-flight that found a device unreachable · `3` nothing failed but the safety gate skipped a device, so not everything ran (the verdict line says how many) · `130` interrupted. A run that reaches its devices also prints a structured summary to stderr (a usage error, a failed pre-flight or an N at the prompt exit before it):

```
[h-ssh] {"targets": 3, "ok": 2, "fail": 1, "skipped": 0, "elapsed_ms": 812, "mode": "show"}
```

`targets` is the number of devices that completed, `skipped` the safety-gate blocks, `mode` one of `show`,
`edit`, `rollback`, `commit`, `batch`, `job`.

## Structured output

`--structured` returns parsed data instead of text where the vendor can provide it. The fallback is per transport, not per command: `ssh`, `openssh` and `telnet*` have no `show_structured`, so they return text as usual; on `junos` a shortcut without a `structured` binding (or a typed command) fails for that device, and on `arista` every command is asked as JSON, so one eAPI cannot render fails. There is no capability list to maintain — a vendor module either implements `show_structured` or it doesn't, and that absence *is* the fallback signal.

```bash
./h-app/h-ssh.py --user admin -sC bgp --structured --json --target R1:10.0.1.1:junos
```

| Vendor | Mechanism | Notes |
|---|---|---|
| `arista` | eAPI JSON | The same request — eAPI already answers in JSON, the text path just flattens it |
| `junos` | PyEZ Table/View over NETCONF | A **different** request: the binding names an RPC, so this is not a parse of the CLI output |
| `ssh`, `openssh`, `telnet` | — | No bindings; always text |

Bindings live in the same `h-app/commands/{vendor}.json` entry as the command, under an optional `structured` key:

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

Output is **vendor-shaped, not normalised** — `bgp` returns the binding's fields (`remote_as`, `is_up`, …) keyed by peer address on a router and eAPI's own JSON on a switch. Nothing here promises the two match, which is why there's no cross-vendor schema to keep in sync. Add bindings one command at a time; without `--structured`, commands without one keep working exactly as before — with it, a junos command without a binding is an error, not text.

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

```python
from hssh import SafetyGate, Target, vendors
from hssh.runner import run_for_target

# straight at a vendor
output = vendors.junos.show("10.0.1.1", "admin", None, "show version", 30, 20)

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

Connection and command timeouts are separate knobs — a slow login and a slow `show route extensive` are different problems.

### Transactions, comments, commit status

A maintenance wants to look at the diff *before* deciding, keep the candidate on the same session, and
find its commits again on the box afterwards:

```python
with vendors.junos.begin(host, user, None, payload, 30, 20) as tx:   # lock, load, diff, commit check
    print(tx.diff)                                                   # tx.show()/tx.rpc() still work here
    if gate_says_yes(tx.diff):
        tx.commit(confirmed=10, comment="C1 cutover")                 # or tx.abort(); leaving the block aborts

vendors.junos.confirm(host, user, None, 30, 20, comment="C1 cutover (confirmed)")
vendors.junos.commit_status(host, user, None, 30, 20)
# [{'seq': 0, 'user': 'h-lab', 'client': 'netconf', 'time': '…', 'epoch': 1792…, 'comment': 'C1 cutover',
#   'note': 'commit confirmed, rollback in 10mins', 'pending_rollback_minutes': 10}, …]

vendors.junos.guarded_commit(host, user, None, payload, 30, 20, minutes=10,
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
hw = vendors.junos.rpc("10.0.1.1", "admin", None, "show chassis hardware", 30, 20)
# -> {'chassis-inventory': [{'chassis': [{'serial-number': [{'data': 'VM6AD25B940C'}], ...}]}]}

vendors.junos.rpc(host, user, None, "get-interface-information", 30, 20,
                  args={"interface-name": "ge-0/0/0", "terse": True})   # RPC name + arguments
vendors.junos.rpc(host, user, None, "show route summary", 30, 20, fmt="xml")   # the reply XML, as text
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
pool.enable()                     # sessions idle 300 s are closed (reaper runs once a minute); pool.enable(idle_timeout=60) or HSSH_POOL_IDLE_TIMEOUT=60 to change

for cmd in ("show version", "show bgp summary", "show route summary"):
    vendors.junos.show("10.0.1.1", "admin", None, cmd, 30, 20)   # one NETCONF session, three RPCs

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
an edit reports `NotAppliedError` if the session died before the lock, and the usual verdicts after. The CLI never enables the pool, so `h-ssh` runs behave exactly as before.

## Package structure

```
h-ssh/
├── h-app/
│   ├── hssh/
│   │   ├── __init__.py      # public API: Target, run_for_target, SafetyGate, pool, vendors; __version__
│   │   ├── core.py          # Target, CSV loader, template resolver, job parser
│   │   ├── cli.py           # argument parsing + orchestration
│   │   ├── runner.py        # concurrent execution engine
│   │   ├── pool.py          # opt-in session pool for library use
│   │   ├── safety.py        # SafetyGate — rate limit + cross-process cooldown
│   │   ├── audit.py         # JSONL audit trail
│   │   ├── errors.py        # NotAppliedError, AmbiguousCommitError — what the retry logic keys on
│   │   ├── commands/        # per-vendor template library: arista.json, junos.json, ssh.json (shipped with the package)
│   │   └── vendors/
│   │       ├── __init__.py  # VENDORS: transport name → module
│   │       ├── junos.py     # PyEZ NETCONF: show, structured, rpc, config transactions, commit-confirmed, commit status
│   │       ├── arista.py    # eAPI
│   │       ├── generic.py   # paramiko SSH
│   │       ├── openssh.py   # the OpenSSH binary — zero dependencies
│   │       └── telnet.py    # raw socket, per-flavour prompt handling
│   ├── commands -> hssh/commands
│   ├── tests/
│   ├── h-ssh.py             # CLI entry point
│   ├── devices.csv          # example inventory
│   ├── example_library_usage.py       # library walkthrough
│   └── custom_automation_example.py   # build on hssh: CSV loader + junos driver
├── .github/workflows/tests.yml   # unit suite, Python 3.10–3.13
├── assets/                  # banner, badges
├── TESTS.md                 # what was run on which code
└── pyproject.toml           # installs the `h-ssh` entry point from h-app/
```

## Develop

```bash
pip install -e '.[dev]'
pytest
```

The unit suite (419 tests) needs no devices and runs on every push to `main` or `develop` and on every pull request (GitHub Actions, Python 3.10–3.13, plain
`python` containers, no JavaScript actions). Beyond it, live runs against Junos vMX routers cover the session pool, the NETCONF
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
