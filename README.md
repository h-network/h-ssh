<div align="center">

<img src="docs/assets/banner.svg" alt="h-ssh — the fleet loop, not the session" width="860">

<br/>

[![Version](https://img.shields.io/badge/version-1.0.0-8B5CF6?style=for-the-badge)](#-quick-start)
![Vendors](https://img.shields.io/badge/vendors-junos_%C2%B7_arista_%C2%B7_ssh_%C2%B7_openssh_%C2%B7_telnet-6366F1?style=for-the-badge)
![Tests](https://img.shields.io/badge/tests-46_unit_%2B_59_live-22c55e?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-64748b?style=for-the-badge)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Runtime dep](https://img.shields.io/badge/runtime_dep-paramiko_only-6366F1?style=flat-square)
![NETCONF](https://img.shields.io/badge/config_writes-PyEZ_NETCONF-84CC16?style=flat-square)
![Size](https://img.shields.io/badge/~2800_lines-pure_Python-8B5CF6?style=flat-square)
![telnetlib](https://img.shields.io/badge/no_stdlib_telnetlib-3.13_ready-475569?style=flat-square)

**h-ssh is the fleet loop, not the session. Point it at one device or three hundred — Juniper, Arista, any SSH box, kit still on a telnet console — and get the output back, in parallel, with the connection handling gone.**

The per-device session is a solved problem; what nobody hands you is everything *around* it. The thread pool. Collecting results per device. Making sure one dead box doesn't sink the run. A rate limiter so you don't hammer a router you've already failed against. A record of what you changed. That's the part you'd otherwise rewrite in every script, and it's what this is.

Reads go over plain SSH because they're cheap; config writes go over NETCONF because they need a lock, a diff, and a rollback. Every edit passes a safety gate, prompts before it commits, and lands in a JSONL audit trail — and `--commit-confirmed` puts the device back the way it was if you never confirm.

[Quick start](#-quick-start) · [Modes](#️-modes) · [Transports](#-transports) · [Structured output](#-structured-output) · [Safety](#-safety) · [Library use](#-library-usage) · [Test results](TESTS.md)

</div>

---

## ✨ What it is

- **🔌 Four transports, one interface.** Juniper (SSH for show, NETCONF for config), Arista (eAPI), any generic SSH device, and raw-socket telnet — including IOS- and Junos-flavoured prompt handling. Same flags whichever you point it at.
- **⚡ Parallel by default.** Devices are worked concurrently behind an `asyncio` semaphore, `--workers 8` out of the box. 3 routers, 3 show commands, ~350 ms end to end.
- **🎯 One command or many, one device or many.** `--batch` runs several commands per device on a single connection; `--job` takes a JSON file with different commands — and different modes — per device, readable from a file or stdin.
- **🛡️ Writes are gated.** Pre-flight reachability check, `y/N` confirmation, `--dry-run` that shows the diff without committing, per-device rate limit and cooldown, and `--commit-confirmed N` for changes that undo themselves if you lose the session.
- **📋 Templates instead of memorised syntax.** `-sC bgp` resolves through a per-vendor JSON template library — *per target*, so the same shortcut sends a Junos router and an Arista switch each their own command. Drop your own in `~/.h-ssh/commands/{vendor}.json` to override.
- **🤖 Built to be scripted.** `--json` on stdout, a structured summary line on stderr, meaningful exit codes, and credentials from `HSSH_USER` / `HSSH_PASSWORD` — or import `hssh` and skip the CLI entirely.
- **🪶 One runtime dependency — or none.** `paramiko`. Vendor libraries are optional extras, telnet is a raw socket (no stdlib `telnetlib`, so it still works on Python 3.13+), and the `openssh` transport drives the system `ssh` binary, so a locked-down jump host with nothing installable still runs the whole tool.

## ⚙️ How it works

```
  devices.csv / --target / --job              per device, up to --workers at once
  ──────────────────────────────────           ─────────────────────────────────────
                    │                          ┌─ junos    show → paramiko SSH
                    ▼                          │           edit → PyEZ NETCONF
        ┌───────────────────────┐              │                  lock → load → diff
        │ safety gate           │              │                  → commit → unlock
        │ rate limit 10/device  │──▶ workers ──┼─ arista   eAPI over HTTPS
        │ cooldown 120s on fail │              ├─ ssh      exec_command
        │ flock'd, cross-process│              ├─ openssh  the ssh binary, no deps
        └───────────────────────┘              └─ telnet   raw TCP + prompt match
                    │                                          │
                    └──────────── every edit ──────────────────┴──▶ audit.jsonl
```

Show commands take the cheap path — a paramiko session with `| no-more` appended — because a read doesn't need a config database. Config changes take the expensive one: PyEZ locks the candidate, loads, diffs, runs `commit_check`, commits, and unlocks, rolling back if any step fails.

## 📦 Install

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

Requires Python 3.10+. Installs an `h-ssh` entry point; the repo's `./h-ssh.py` works uninstalled too.

## 🚀 Quick start

```bash
# show command across two routers, inline targets
./h-ssh.py --user admin -sC bgp --target R1:10.0.1.1:junos --target R2:10.0.1.2:junos

# ... or from a CSV inventory, as JSON
./h-ssh.py --user admin --json -sC "show version" --devices devices.csv

# compare one command's output across the fleet
./h-ssh.py --user admin -sC bgp --diff --target R1:10.0.1.1:junos --target R2:10.0.1.2:junos

# config change — look before you leap
./h-ssh.py --user admin -eC "set system ntp server 10.0.0.1" --dry-run
./h-ssh.py --user admin -eC "set system ntp server 10.0.0.1" -y

# a change that rolls itself back in 10 minutes unless you confirm
./h-ssh.py --user admin -eB configs/all.set --commit-confirmed 10 -y

# several commands per device, one connection
./h-ssh.py --user admin --batch commands.txt --target R1:10.0.1.1:junos

# a console server still speaking telnet
./h-ssh.py --user admin -sC "show version" --target SW1:10.0.0.1:5000:telnet-ios
```

Targets are `NAME:HOST:VENDOR` or `NAME:HOST:PORT:VENDOR`. A CSV inventory accepts `name,ip`, `name,ip,vendor`, headers or none, and `#` comments.

**A target that doesn't declare a vendor is treated as plain `ssh`** — the transport that assumes least, since its show and edit paths are both `exec_command`. Declare `junos` or `arista` explicitly to get NETCONF or eAPI. Command shortcuts resolve per target against that vendor, so one `-sC bgp` across a mixed inventory sends each device its own command.

### Authentication

```bash
./h-ssh.py --user admin -sC bgp                     # SSH agent / key, no password
./h-ssh.py --user admin --password secret -sC bgp   # explicit
export HSSH_USER=admin HSSH_PASSWORD=secret         # or from the environment
```

## 🎛️ Modes

| Flag | Mode | What it does |
|---|---|---|
| `-sC` | Show | Run a show/display command (or a template name) |
| `-eC` | Edit command | Apply one config line to every target |
| `-eD` | Edit directory | Per-device config from `<NAME>.set` files |
| `-eB` | Edit broadcast | One config file applied to all targets |
| `--batch` | Batch | Several show commands from a file, one connection per device |
| `--job` | Job | Per-device commands *and* modes from JSON — file or `-` for stdin |

```json
[
  {"target": "R1:10.0.1.1:junos", "show": "show bgp summary"},
  {"target": "R2:10.0.1.2:junos", "show": "show version"},
  {"target": "R3:10.0.1.3:junos", "edit": "set system host-name R3-new"}
]
```

```bash
./h-ssh.py --user admin --job jobs.json --json
cat jobs.json | ./h-ssh.py --user admin --job - --json
```

## 🔌 Transports

| Vendor | Transport | Library | Show | Edit |
|---|---|---|---|---|
| `junos` | SSH + NETCONF | paramiko + junos-eznc | paramiko `exec_command` | PyEZ lock/load/diff/commit |
| `arista` | eAPI (HTTPS) | pyeapi | eAPI enable | eAPI config |
| `ssh` | SSH | paramiko | `exec_command` | `exec_command` |
| `openssh` | OpenSSH client | built-in | `ssh host cmd` | `ssh host cmd` |
| `telnet` | Raw socket | built-in | raw TCP | config mode |
| `telnet-ios` | Raw socket, IOS prompts | built-in | raw TCP | `configure terminal` |
| `telnet-junos` | Raw socket, Junos prompts | built-in | raw TCP | `configure` / `commit` |

Every transport reuses a single connection per device for batch work.

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
./h-ssh.py --target R1:10.0.1.1:openssh -sC "show version" --user admin
```

It inherits your `~/.ssh/config`, keys, agent and `known_hosts`, so jump-host `ProxyJump` stanzas and
per-host identities work with no extra flags. Host key policy defaults to `accept-new`; override with
`HSSH_HOST_KEY_POLICY=yes` (strict) or `no` (skip).

Two limits, both deliberate: `--structured` has no bindings here, and `--commit-confirmed` is
rejected rather than silently ignored — a confirmed commit needs the NETCONF `junos` transport, and
dropping the rollback timer without saying so would be worse than refusing.

## ⚙️ Defaults

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

Precedence is flag → environment → config file → built-in default. A value given on the command
line always wins, and `--user` additionally falls back to `HSSH_USER` then the prompt, which offers
your system username so Enter accepts it.

`session_timeout` is the one worth setting. It defaults to 30s, which is how long every unreachable
device costs you; on a LAN a reachable device connects in well under a second.

**Passwords are never read from this file.** A config file on a shared jump host is the wrong place
for a secret; use `HSSH_PASSWORD`, `--password`, the prompt, or keys. `--config PATH` points at a
different file.

## 📤 Output

| Flag | Prints |
|---|---|
| *(none)* | one status line per device |
| `-v` | status plus a framed block per device |
| `--raw` | device output only, nothing else on stdout |
| `--json` | one object per device, with `command` and `output` fields |

`--raw` is the pipe-friendly one: no banner, no progress lines, no summary. Each device gets a
`name:` line and its output, and that is all stdout carries — failures and the verdict go to stderr,
so `--raw > out.txt` keeps the file clean even on a partial run.

```console
$ h-ssh -sC "show version | match Junos:" --raw
cr1:
Junos: 24.2R1-S2.5

cr2:
Junos: 24.2R1-S2.5
```

`--raw`, `-v` and `--json` are mutually exclusive; asking for two is an error rather than a silent
preference. The command echo (`$ show version`) belongs to the framed view — `--raw` and `--json`
both drop it, and `--json` reports it as its own `command` field instead of repeating it inside
`output`.

## ⏱️ Failure handling

A device that black-holes packets used to cost the full timeout three times over. Failures are now
classified before anything is retried:

| Failure | Behaviour |
|---|---|
| Unreachable — timed out, refused, no route, network unreachable | fail immediately |
| Authentication, host key, unresolvable name, rejected command | fail immediately |
| Failures *after* connecting — command timeout, reset, broken pipe | retried, `--retries` times (default 2) |

The split is whether a connection was established. A connect-phase failure has already spent the
full `ConnectTimeout`; spending it twice more is what lets one dead device dominate a fleet run.
Unreachable means unreachable for the duration of the run. Once a session exists, a failure may well
be transient, so those still get retried.

Retrying an authentication failure cannot succeed either, and on a fleet it spends three real login
attempts per device against accounts that may lock out. Those stop at one.

One unreachable device in a three-device lab run, at default settings: **28s** before, **8s** now —
a single timeout rather than three plus backoff.

`--workers` is honoured literally, up to 256. The vendor calls block, so each in-flight device holds
a thread; h-ssh sizes the executor to `--workers` rather than leaving it at asyncio's default of
`min(32, cpu+4)`, which on a 2-vCPU jump host is **6 threads no matter what you asked for** — and a
device stuck in a 30s connect timeout holds one of those six the whole time.

Ctrl-C stops the run, reports which devices finished, and exits `130`. Output already written to
stdout stays valid; the interrupted notice goes to stderr, so a truncated `--raw` run cannot look
like a complete one.

## 🔒 Safety

Layered, and every layer is off the critical path until you ask for a write.

| Guard | Flag | Behaviour |
|---|---|---|
| Pre-flight check | *(automatic)* | Edits verify reachability before touching config |
| Confirmation | *(automatic)* | Edits prompt `y/N`; `-y` to skip in automation |
| Dry run | `--dry-run` | Loads and diffs the candidate, never commits |
| Commit confirmed | `--commit-confirmed N` | Junos rolls back after N minutes unless confirmed |
| Safety gate | `--safety-file PATH` | 10 attempts per device per run; 120 s cooldown after a failure, held in a `flock`'d JSON file so it survives across processes |
| Audit trail | `--audit-log PATH` | Every edit appended as JSONL |

The gate is deliberately fail-closed: a device is marked active *before* the attempt, so a crash mid-run leaves it blocked rather than open.

Exit codes: `0` success · `1` a device failed · `2` usage error. Every run also prints a structured summary to stderr:

```
[h-ssh] {"targets":3,"ok":2,"fail":1,...}
```

## 🧬 Structured output

`--structured` returns parsed data instead of text where the vendor can provide it, and falls back to the normal text path where it can't. There is no capability list to maintain — a vendor module either implements `show_structured` or it doesn't, and that absence *is* the fallback signal.

```bash
./h-ssh.py --user admin -sC bgp --structured --json --target R1:10.0.1.1:junos
```

| Vendor | Mechanism | Notes |
|---|---|---|
| `arista` | eAPI JSON | The same request — eAPI already answers in JSON, the text path just flattens it |
| `junos` | PyEZ Table/View over NETCONF | A **different** request: the binding names an RPC, so this is not a parse of the CLI output |
| `ssh`, `openssh`, `telnet` | — | No bindings; always text |

Bindings live in the same `commands/{vendor}.json` entry as the command, under an optional `structured` key:

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

Output is **vendor-shaped, not normalised** — `bgp` returns Junos field names on a router and eAPI's own JSON on a switch. Nothing here promises the two match, which is why there's no cross-vendor schema to keep in sync. Add bindings one command at a time; commands without one keep working exactly as before.

## 🧩 Library usage

```python
from hssh import Target, vendors
from hssh.runner import run_for_target

# straight at a vendor
output = vendors.junos.show("10.0.1.1", "admin", None, "show version", 30, 20)

# or through the runner, with the safety gate in place
target = Target(name="R1", host="10.0.1.1", vendor="junos")
name, ok, output, ms = run_for_target(
    t=target, transport="junos", mode="show",
    show_cmd="show version", edit_cmd=None,
    config_dir=None, broadcast_file=None,
    user="admin", passwd=None,
    session_timeout=30, command_timeout=20,
    dry_run=False, commit_confirmed=None, save_dir=None,
)
```

Connection and command timeouts are separate knobs — a slow login and a slow `show route extensive` are different problems.

## 📁 Package structure

```
h-ssh/
├── hssh/
│   ├── core.py          # Target, CSV loader, template resolver, job parser
│   ├── cli.py           # argument parsing + orchestration
│   ├── runner.py        # concurrent execution engine
│   ├── safety.py        # SafetyGate — rate limit + cross-process cooldown
│   ├── audit.py         # JSONL audit trail
│   └── vendors/
│       ├── junos.py     # paramiko show + PyEZ NETCONF config
│       ├── arista.py    # eAPI
│       ├── generic.py   # paramiko SSH
│       ├── openssh.py   # the OpenSSH binary — zero dependencies
│       └── telnet.py    # raw socket, per-flavour prompt handling
├── commands/            # per-vendor template library (JSON)
├── tests/
├── h-ssh.py             # CLI entry point
└── devices.csv          # example inventory
```

## 🧪 Tests

46 unit tests, plus 59 live integration tests run against three Junos vMX routers on 24.2R1-S2.5 — covering every mode, both edit paths, concurrency, error handling, exit codes, and the safety gate. Full breakdown in [TESTS.md](TESTS.md).

```bash
pip install -e '.[dev]'
pytest
```

## 🔗 See also

- [`h-network/junos-mcp-server`](https://github.com/h-network/junos-mcp-server) — the same device access exposed to an LLM over MCP
- [`h-network/h-cli`](https://github.com/h-network/h-cli) — AI-driven infrastructure management this feeds into

## 📄 License

MIT — see [LICENSE](LICENSE).
