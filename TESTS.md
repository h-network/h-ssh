# Test Results

Two kinds of evidence: the unit suite, which needs no devices and runs on every push and pull
request (GitHub Actions, Python 3.10–3.13), and live runs against Junos vMX routers, listed with the
code state they were run on.

## Unit Tests — 303/303 passed

`pip install -e '.[dev]' && pytest` from the checkout root (`develop`, 2026-10-21).

| Suite | Tests | Covers |
|-------|------:|--------|
| test_audit.py | 6 | JSONL audit trail, 0600, redaction, graceful failure |
| test_cli_edit_output.py | 13 | default-mode verdict + diff for edits, the commit-confirmed reminder |
| test_cli_junos_safety.py | 10 | Junos set-syntax guard, show-batch error handling, `--rollback`/`--comment`/`--show-diff`/`--commit-status` usage errors |
| test_config.py | 17 | `~/.h-ssh/config`, precedence flag → env → file → default |
| test_core.py | 11 | targets, CSV inventory, template resolution, job parsing |
| test_format.py | 20 | `--format json\|xml` through `rpc()`/`rpc_batch()`, refusal on other transports, `--json`/`--raw`/`-v`/`--diff` shapes |
| test_job.py | 11 | `--job` files and stdin |
| test_junos.py | 36 | PyEZ driver: show, batch, edit sequence, dry-run, commit-confirmed, the commit edge cases, `rollback()`, `begin()`/`Transaction`, comments, `guarded_commit()` |
| test_openssh.py | 25 | the OpenSSH-binary transport, `SSH_ASKPASS`, ControlMaster |
| test_packaging.py | 1 | wheel contents |
| test_pool.py | 35 | session pool: reuse per `(host, port, user)`, stale detection and probe, discard rules on every edit failure, reopen-once for reads, threads never share a session, reaper, `close_all`, re-entrancy |
| test_raw.py | 10 | `--raw` output contract |
| test_retry.py | 34 | failure classification (incl. PyEZ connect-phase names), backoff, edits retried only on `NotAppliedError` |
| test_rpc.py | 18 | `rpc()`: CLI-command translation, RPC name + args, JSON/XML, never re-sending non-reads, `rpc_batch()`, `commit_status()` |
| test_runner_edit.py | 22 | runner policy: dry-run and commit-confirmed refusals, retry rule, confirm, rollback mode, comments, commit-status mode |
| test_safety.py | 19 | SafetyGate rate limit, cooldown, flock, corrupt-file handling |
| test_structured.py | 9 | `--structured` bindings and fallback |
| test_telnet.py | 6 | raw-socket telnet prompts and config mode |

## Live checks on `develop` — lab AX4 + PE1, vMX 24.2R1-S2.5 (2026-10-20/21)

Two routers, user with key auth, NETCONF on 830 (AX4 reachable on 22 until its lo0 filter got an
`acc-netconf` term — committed through h-ssh itself: `-eB … --dry-run`, then `--commit-confirmed 5`,
verified over 830, then `-eC commit`). Every item below was run on the pooled code unless noted.

| # | Check | Result |
|---|-------|--------|
| 1 | Session pool: 12 pooled calls → 1 NETCONF session per router, confirmed by the router's own `show system connections`; 3,371-line `show configuration \| display set` 0.79 s cold / 0.35 s reused vs 0.82–0.87 s per unpooled `show version` | Pass |
| 2 | 6 concurrent threads on 2 routers: never two RPCs in flight on one session, 0 new sessions, 0.55 s wall | Pass |
| 3 | Session closed behind the pool's back → reopened transparently; probe RPC on a live session → reused, not reopened | Pass |
| 4 | `--dry-run` edit on a pooled session → diff returned, candidate clean afterwards (`Config.diff()` is None) | Pass |
| 5 | Reaper closes idle sessions; `close_all()` leaves no session on the router | Pass |
| 6 | Maintenance-style flow on one pooled session: show → configure + commit check + `commit confirmed 5` → shows every 30 s for 3.5 min → confirm at 214 s → verify → undo with a plain commit; `opens 1, reuses 30, discards 0` | Pass |
| 7 | `rpc()`: CLI command → router's JSON (chassis serial read back), RPC name + args (`ge-0/0/0 up`), XML (43 lines), invalid command → PyEZ `RpcError: syntax error`; four calls, one session | Pass |
| 8 | `get-configuration` as JSON: whole config (AX4 143 KB, 195 interfaces) in 2 s; unit, BGP neighbor (incl. encoded key), policy, VPLS instance, IRB, CoS and filter stanzas sliced by name; deactivated stanzas carry `"@": {"inactive": true}` | Pass |
| 9 | State RPCs with static labels: interface, BGP neighbor/summary, BFD, received/advertised routes, ARP, ND, firewall counters, CoS, VPLS connections, VPLS MAC table, LDP sessions — all JSON | Pass |
| 10 | `--commit-status` (text and `--json`): 50-entry history with epochs; library `commit_status()` same | Pass |
| 11 | `--format json` on `-sC` (incl. a shortcut ending in `\| no-more`), `--format xml` on `--batch` (two documents) | Pass |
| 12 | `h-app/` layout: installed `h-ssh` from another cwd resolves templates; `./h-app/h-ssh.py` from the root; `--batch` on both routers | Pass |
| 13 | Functioning sweep, groups 1–2 (show/output modes, inventory forms, exit codes; `--batch`/`--job`/`--structured`/`--workers`): 42 + ~40 invocations on the code *before* the pool; findings not yet verified | Ran, unverified |

Observed on the way, not h-ssh defects: `\| match` is ignored over NETCONF (`\| display set` works; use
`rpc()` for data); AX4 (a vMX) went down twice during the day — once while a `--dry-run` commit check
was in flight, once during read-only polling — with no core dump and a clean reboot reason.

## Before release 1

| Item | State |
|------|-------|
| Functioning sweep, all 5 groups, on current `develop` (groups 3–5: failure handling, edit safety with `--dry-run`, library API) | pending, needs the lab |
| Live, one real commit each: `--rollback N`, `begin()`/`Transaction` commit and abort, `--comment` visible in `--commit-status`, `guarded_commit()` on the rollback path, `--show-diff`, `--format` on a `--job` | pending, needs the lab |
| `develop` → `main`, tag `v1.0.0` | after the two above |

## Earlier live run — 59/59 passed (3 × vMX 24.2R1-S2.5, code before the session pool)

| # | Test | Result |
|---|------|--------|
| 1 | Show commands across 3 routers in parallel (~350ms) | Pass |
| 2 | BGP template shortcut resolution | Pass |
| 3 | Cross-device diff (`--diff`) | Pass |
| 4 | Batch mode — 3 commands per device, single SSH connection | Pass |
| 5 | Job mode — per-device commands from JSON file | Pass |
| 6 | Dry-run edit + audit log (no commit) | Pass |
| 7 | NETCONF edit — lock, load, diff, commit, unlock | Pass |
| 8 | Config verification after edit | Pass |
| 9 | Save output to per-device files (`--save-output`) | Pass |
| 10 | Safety gate wiring through runner | Pass |
| 11 | Command templates — Junos (15) and Arista (8) | Pass |
| 12 | Edit broadcast — same config to 3 routers in parallel | Pass |
| 13 | Job mode via stdin pipe (`--job -`) | Pass |
| 14 | Safety gate with edit + file persistence | Pass |
| 15 | Parallel execution — 3.0x speedup confirmed | Pass |
| 16 | Mixed reachable/unreachable hosts — partial failure handling | Pass |
| 17 | Invalid credentials — clean `Authentication failed.` error | Pass |
| 18 | Unknown vendor — clean error, exit 2 | Pass |
| 19 | Mutually exclusive CLI flags — clean error, exit 2 | Pass |
| 20 | No execution mode — clean error, exit 2 | Pass |
| 21 | Empty command string — clean error, exit 2 | Pass |
| 22 | Pipe and quotes in command (`show version \| match "Junos:"`) | Pass |
| 23 | Invalid Junos config — NETCONF ConfigLoadError, no commit, rollback | Pass |
| 24 | Explicit port `:22` | Pass |
| 25 | Wrong port `:12345` — `Unable to connect` error | Pass |
| 26 | Idempotent edit (no change) — returns `NO CHANGES` | Pass |
| 27 | Multi-line config in single `-eC` | Pass |
| 28 | Environment variable authentication (`HSSH_USER`) | Pass |
| 29 | Pre-flight check blocks edit to unreachable device | Pass |
| 30 | Batch with single command | Pass |
| 31 | Generic SSH transport (`--target R1:...:ssh`) | Pass |
| 32 | Large output — full config dump (52 lines) | Pass |
| 33 | Edit directory mode (`-eD`) — per-device `.set` files | Pass |
| 34 | Missing device config file in `-eD` — partial failure | Pass |
| 35 | Empty batch file — clean error | Pass |
| 36 | Invalid JSON job file — parse error | Pass |
| 37 | Mixed show+edit in single job file | Pass |
| 38 | Batch with comments and blank lines — filtered correctly | Pass |
| 39 | Same host targeted twice — both execute independently | Pass |
| 40 | Complex piped Junos command | Pass |
| 41 | Diff with identical output — shows `(identical)` | Pass |
| 42 | Audit log integrity — valid JSONL, all entries present | Pass |
| 43 | Target parsing — all formats, hostnames, edge cases | Pass |
| 44 | Python library API — direct vendor call + runner | Pass |
| 45 | Save output + JSON combined | Pass |
| 46 | Non-existent batch file — clean error | Pass |
| 47 | Concurrent NETCONF edits — lock serialization | Pass |
| 48 | Safety gate cooldown — 120s block after failure | Pass |
| 49 | Safety gate rate limit — blocked without release | Pass |
| 50 | Help output | Pass |
| 51 | Package version + exports | Pass |
| 52 | Template shortcuts (ospf, isis, routes) | Pass |
| 53 | Rapid-fire 5 sequential runs | Pass |
| 54 | Verbose log file (`--log`) | Pass |
| 55 | JSON output validation — all modes | Pass |
| 56 | Stderr summary JSON validation | Pass |
| 57 | Custom user command templates (`~/.h-ssh/commands/`) | Pass |
| 58 | Exit codes — 0 success, 1 device fail, 2 user error | Pass |
| 59 | Full lifecycle — apply, verify, revert, verify across 3 routers | Pass |
