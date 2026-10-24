# Test Results

Two kinds of evidence: the unit suite, which needs no devices and runs on every push and pull
request (GitHub Actions, Python 3.10–3.13), and live runs against Junos vMX routers, listed with the
code state they were run on.

## Unit Tests — 419/419 passed

`pip install -e '.[dev]' && pytest` from the checkout root (`develop` 9462f99, 2026-10-21). The
standalone review of `develop` (18 items, issues #23–#29, PRs #30–#36) added 110 regression tests;
every one was run against the code before its fix and failed there.

| Suite | Tests | Covers |
|-------|------:|--------|
| test_audit.py | 8 | JSONL audit trail, 0600, redaction (text and JSON values), `secure_append`, graceful failure |
| test_cli_edit_output.py | 24 | default-mode verdict + diff for edits, the commit-confirmed reminder, `--show-diff` preview → prompt → commit and the abort paths, confirm hint from `sys.argv[0]` and job targets, `--log` 0600 + redacted |
| test_cli_junos_safety.py | 12 | Junos set-syntax guard (also through `--transport junos`), show-batch error handling, `--rollback`/`--comment`/`--show-diff`/`--commit-status`/`--format` usage errors |
| test_config.py | 24 | `~/.h-ssh/config`, precedence flag → env → file → default, `transport` reaching undeclared targets (flag, file, inline/CSV/job forms, declared vendor wins) |
| test_core.py | 14 | targets (incl. `NAME:[v6]:vendor:port`), CSV inventory, the one set-file reader (inline `#` kept), template resolution, job parsing |
| test_format.py | 21 | `--format json\|xml` through `rpc()`/`rpc_batch()`, refusal on other transports and on edits, `--json`/`--raw`/`-v`/`--diff` shapes |
| test_generic.py | 15 | paramiko transport: host keys pinned in `~/.h-ssh/known_hosts` (0600), `HSSH_HOST_KEY_POLICY`, changed key refused, parallel first contacts, exit status → failure |
| test_job.py | 16 | `--job` files and stdin, `default_vendor`, same device twice (entries carried with their results) |
| test_junos.py | 45 | PyEZ driver: show, batch, edit sequence, dry-run, commit-confirmed, the commit edge cases, `rollback()`, `begin()`/`Transaction`, comments, `confirm()` under the lock, `guarded_commit()` and its history check, `expected_diff` |
| test_openssh.py | 26 | the OpenSSH-binary transport, `SSH_ASKPASS`, ControlMaster, `--` before the host |
| test_packaging.py | 1 | wheel contents |
| test_pool.py | 43 | session pool: reuse per `(host, port, user)`, stale detection and probe, discard rules on every edit failure, reopen-once for reads, threads never share a session, reaper, `close_all`, re-entrancy, a nested borrow never closes the session under an open transaction |
| test_raw.py | 10 | `--raw` output contract |
| test_retry.py | 41 | failure classification (PyEZ connect phase by its prefix, `invalid` narrowed), backoff, edits retried only on `NotAppliedError` |
| test_rpc.py | 19 | `rpc()`: CLI-command translation, RPC name + args, JSON/XML, never re-sending non-reads, `rpc_batch()`, `commit_status()` (pending only on the latest commit) |
| test_runner_edit.py | 26 | runner policy: dry-run and commit-confirmed refusals, retry rule, confirm, rollback mode, comments, commit-status mode, `-eD`/`-eB` load the same lines, no resolver call |
| test_safety.py | 21 | SafetyGate rate limit, cooldown, flock (one yield: an `OSError` in the body propagates), corrupt-file handling |
| test_structured.py | 9 | `--structured` bindings and fallback |
| test_telnet.py | 33 | raw-socket telnet on a scripted fake server: readers raise on timeout/EOF, failed login detected, silent console gets one Enter, `configure exclusive`, anchored error match, commit outcome unknown, best-effort cleanup |

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
| 14 | `confirm()` under the lock (PR #32): `commit confirmed 3` from one session; another session's uncommitted edit in the shared candidate → `confirm()` refused (`configuration database modified`, nothing sent); from a clean session the locked plain commit confirmed it; 187 s later the change was still there with no pending entry; undone with a plain commit. Found on the way: the router keeps the "commit confirmed, rollback in 3mins" note on the old entry after the confirm, so `pending_rollback_minutes` is now a sequence-0 fact | Pass |
| 15 | Release gate on 9462f99, 29 checks (table below) | Pass |

Observed on the way, not h-ssh defects: `\| match` is ignored over NETCONF (`\| display set` works; use
`rpc()` for data); AX4 (a vMX) went down twice during the day — once while a `--dry-run` commit check
was in flight, once during read-only polling — with no core dump and a clean reboot reason.

### Release gate on `develop` 9462f99 (2026-10-21) — 29/29 passed

`~/h-sshScripts/lab_release_gate.py`: AX4 takes the edits (always the lo0 description, always undone),
PE1 is read only, CLI calls paced for the router's `ssh rate-limit 10`. First run: 26/29, the three
misses were in the script (a `#` after a closing quote is not Junos syntax and the router says so;
an operator's `n` exits 0 by design; a rollback transaction answers `ROLLBACK 1: COMMIT OK`); fixed and
re-run clean.

| # | Check | Result |
|---|-------|--------|
| 3.1–3.2 | Unreachable host, wrong port: exit 1, clean error, no traceback | Pass |
| 3.3 | Unknown user: exit 1, one attempt (permanent), auth error named | Pass |
| 3.4 | Invalid show command: exit 1, the router's `syntax error` | Pass |
| 3.5 | Reachable + unreachable in one run: exit 1, AX4 ok, the other failed, in `--json` | Pass |
| 3.6 | Invalid job file: exit 2 before any session | Pass |
| 3.7 | `--transport junos` applies the set-syntax guard to an undeclared target (#24) | Pass |
| 3.8 | `--format` with an edit refused, exit 2 (#26) | Pass |
| 3.9 | `--show-diff` without a terminal refused before any preview (#26) | Pass |
| 3.10 | `R1:[2001:db8::1]:junos` parses (#27) | Pass |
| 4.1 | `--dry-run` edit: `DRY-RUN` + diff, candidate untouched | Pass |
| 4.2 | `-eD` with `description "h-ssh-gate#2"`: the dry-run diff carries the value as written (#23) | Pass |
| 4.3 | `--log` file is 0600 and the SNMP community in it is `[REDACTED]` (#26) | Pass |
| 4.4 | `--commit-confirmed 1 --comment` → pending entry with the comment; `-eC commit --comment` → locked confirm, no pending entry, confirm at seq 0; the change survived the timer | Pass |
| 4.5 | `--rollback 2 --comment`: lo0 back to before, the comment in `show system commit` | Pass |
| 4.6 | `--show-diff` on a pty: `n` → diff shown, `Aborted by user`, nothing committed; `y` → the previewed diff committed with its comment | Pass |
| 4.7 | Undo with a plain commit | Pass |
| 5.1 | `begin()`: diff, `tx.show()` and a plain `show()` nested on the same pooled session (#22), `abort()` leaves nothing | Pass |
| 5.2 | `Transaction.commit(comment=)`, then `begin(rollback=1)`: diff shows the removal, `ROLLBACK 1: COMMIT OK` | Pass |
| 5.3 | `guarded_commit()` with a failing check: `rollback 1` at once, comment `… (rolled back: checks failed)`, no pending entry, lo0 as before | Pass |
| 5.4 | `guarded_commit()` with a passing check: confirmed under the lock, comment `… (confirmed)`, no pending entry | Pass |
| 5.5 | Undo through `edit()` | Pass |
| 5.6 | `rpc()` JSON and XML, `rpc_batch()` on the pooled session | Pass |
| 5.7 | One NETCONF session for the whole library section (`opens 1, reuses 24`) | Pass |
| 5.8 | `--format json` on a `--job` with a show entry per router: both answer with JSON data | Pass |

## Before release 1

| Item | State |
|------|-------|
| Functioning sweep, all 5 groups, on current `develop` (groups 3–5: failure handling, edit safety with `--dry-run`, library API) | done, release gate above (groups 1–2 ran on the code before the pool) |
| Live, one real commit each: `--rollback N`, `begin()`/`Transaction` commit and abort, `--comment` visible in `--commit-status`, `guarded_commit()` on the rollback path, `--show-diff`, `--format` on a `--job` | done, release gate 4.4–5.8 |
| Standalone review of `develop`: 18 items verified, issues #23–#29, PRs #30–#36 merged | done |
| `develop` → `main`, tag `v1.0.0` | ready |

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
| 11 | Command templates — Junos (15) and EOS (8, for the dialect to come) | Pass |
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
