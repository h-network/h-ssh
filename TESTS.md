# Test Results

Two kinds of evidence: the unit suite, which needs no devices and runs on every push and pull
request (GitHub Actions, Python 3.10–3.13), and live runs against Junos vMX routers, listed with the
code state they were run on.

## Unit Tests — 947/947 passed

`pip install -e '.[dev]' && pytest` from the checkout root (`feat/fleet`, 2026-10-25, with the dialect /
transport / driver split of #80–#84 complete, the store hardening and the `Fleet` library API). The standalone review of `develop` (18
items, issues #23–#29, PRs #30–#36) added 110 regression tests; every one was run against the code
before its fix and failed there.

The suite is laid out by layer where the package is: `tests/dialects` (what each dialect knows),
`tests/drivers` (the registry, the contract, the typed results), `tests/transports` (the CLI engine on
a scripted channel), and the transport, runner and CLI tests at the top level. `tests/fixtures/` holds
the packages the entry-point tests load, not tests: `hssh_dummy` registers `dummy@ssh` on the paramiko
transport, `hssh_broken` raises `ImportError` on import, `hssh_taken` claims names the registry already
has. No test opens a connection to a real device: paramiko, PyEZ and the `ssh` binary are faked, and
telnet runs against a scripted server on localhost.

| Suite | Tests | Covers |
|-------|------:|--------|
| dialects/test_dialects.py | 15 | #81: vendor knowledge lives with the dialect — the set-syntax guard, the refusal regexes, the prompts, the commit-pending note, the read rule — and core, cli, runner and the telnet module ask it |
| drivers/test_contract.py | 22 | #80: every registered driver's `supports` is backed by its module's signatures (`violations()`); a module serving one driver declares everything it has, shared modules offer what every dialect on them declares; a stub that falls short is named, `*args` satisfies the contract |
| drivers/test_registry.py | 15 | #80: `dialect@transport` names with today's names as aliases, the retired `arista` line, what each transport says of itself, `supports` per driver, every driver resolving to its transport's module, stand-ins in `drivers.MODULES`, default ports and install hints from the transport, the CLI taking a canonical target |
| drivers/test_results.py | 37 | #82: `EditResult`, `BatchResult` and `CommitStatus` still the text or list they were, `RunResult` unpacking as the old tuple with `.result` and `.error`, parsing that never changes the text, pickle and copy |
| test_watch.py | 4 | `--every SECONDS [--times N]`: every tick a run in the store, one line per tick and the unified diff for every device whose reply changed since the tick before (a device that fails shows `OK -> FAIL`), no per-device chatter, the summary line once per tick; Ctrl-C between ticks says how many ticks are kept (exit 130); refused with `--times` alone, `--no-store`, an edit, or under one second |
| transports/test_cli.py | 21 | #83: the CLI engine (`hssh/transports/cli.py`) on an in-memory channel — login, learning the prompt, paging, candidate and lines edits, confirm, a refusal read past its redraw |
| test_entry_points.py | 19 | #84: a driver from an `hssh.drivers` entry point loads after the built-ins and `SOURCES` names the entry point (or the distribution); a broken one is listed by name and the rest still load; a taken name or alias, an object that is not a `Driver`, a driver listed twice refuse the whole entry point; `--list-vendors` shows the row and the broken line; the contract and the runner take the driver, a stand-in in `drivers.MODULES` does its work; h-ssh's own `builtin` entry point is never loaded twice; `pyproject.toml` declares it |
| test_audit.py | 32 | JSONL audit trail, 0600 whatever the umask, redaction (text, XML and JSON values; the type words stay), `secure_append`/`secure_write` refusing a planted symlink or FIFO, graceful failure |
| test_bare_hosts.py | 10 | targets typed bare on the command line: a host alone is a device named after itself on `--transport` (an IPv6 host in brackets), `name:host[:vendor][:port]` works bare, before or between the flags, adds up with `--target`, and silences the inventory file; `--target` itself stays strict; a device twice is refused as before; `--help` shows `HOST`; a bare host's confirm hint stays bare |
| test_cli_edit_output.py | 39 | default-mode verdict + diff for edits, the commit-confirmed reminder, `--show-diff` preview → prompt → commit and the abort paths, confirm hint from `sys.argv[0]` and job targets, a job naming one device twice, `--log` 0600 + redacted, a malformed target as a usage error |
| test_cli_junos_safety.py | 12 | Junos set-syntax guard (also through `--transport junos`), show-batch error handling, `--rollback`/`--comment`/`--show-diff`/`--commit-status`/`--format` usage errors |
| test_cli_runfile.py | 26 | #60: `--run FILE` in YAML or JSON — every key a flag, the command line wins, no credential in the file, relative paths against the file, an edit from a file needs a timer or a dry run, YAML without PyYAML is a clear error |
| test_config.py | 25 | `~/.h-ssh/config`, precedence flag → env → file → default, a credential line refused with exit 2 (never read, never ignored), `transport` reaching undeclared targets (flag, file, inline/CSV/job forms, declared vendor wins) |
| test_credentials.py | 9 | no `--password` flag: `HSSH_PASSWORD` for a pipeline (set but empty refuses the run), the prompt by hand (Enter skips to keys, Ctrl-D is one line and exit 2, the first Ctrl-C ends the run), the variable set by hand means no prompt, no `--user`/`HSSH_USER`/config `user` means the name you are logged in as with no question (`HSSH_USER` still wins), `--help` says where the password comes from |
| test_core.py | 34 | targets (incl. `NAME:[v6]:vendor:port`), CSV inventory, device names that stay inside their directory, the one set-file reader (inline `#` kept), shortcut resolution, job parsing, the pre-flight banner rule, the retired `arista` line |
| test_error_classification.py | 29 | #65: a failure the same call cannot fix is reported once, in words that say what happened; a device the operator interrupted while it was still being connected to is interrupted, not failed |
| test_fail_closed.py | 13 | #64: a run finds out before the first device that it cannot do its job — an audit or run log that cannot be written, a safety file that cannot be kept, a device without its set file, a device listed twice or under two names |
| test_fleet.py | 58 | the `Fleet` library API (`hssh/fleet.py`, `hssh/limits.py`): results as values in completion order (a slow device last, every device arrives), at most `workers` devices in flight (the first three held on a barrier, so the peak is not the scheduler's) and `workers` fitted to the open-file limit (the CLI's rule, now in `hssh/limits.py`), a failure as a value with the rest still running, retries by the runner's classification (2 by default, as the CLI), a transport call that never returns given up on within the bound (the SSH transports' three connect phases counted, NETCONF's one deadline), the queue behind held workers failed at once, a held worker released when its call returns, a wedged device failed at once by later runs on the same Fleet instead of poisoning them, the worker pool's daemon threads with concurrent.futures semantics, a script that gave up on a wedged device exiting without waiting for it, `batch` one answer per command, `async for` the same set with SQLite and the host name off the event loop, a cancelled async consumer leaving the run intact (iterating again fails the queue it had given up on, the held call returned or not, so the run ends and the next one starts), `async with` closing off the loop, `to_dicts()` JSON-serialisable in the CLI's record shape, `fmt="json"` as data and refused on a text transport, breaking out early loses nothing, one run at a time (a second run while devices are in flight refused, a finished unread run wrapped up first), close() from a watchdog thread during iteration (many rounds with a store: no exception, every step run, nothing leaked), close() keeping the results of devices that finished unconsumed and recording a run left unfinished as interrupted, after close() only what was done by then (a late answer dropped, its row saying skipped; sync and async), `close(wait=)` yielding the device that answered inside the grace, the store's run row and one row per result from the iterating thread (a caller's `Store` left open), store loss counted in `not_kept`/`store_error` and said as the CLI says it, with the run named, but never raised (a failed write; the file deleted under the run: every result, the run row left open), sessions pooled for the Fleet's lifetime (opens == devices across two runs, closed on exit; two Fleets share the pool, a caller's pool left alone; NETCONF over a fake PyEZ logs in once per device), every target form (bare host, `name:host[:vendor][:port]`, `Target`, CSV by `Path`, one string as file or target, a mistyped inventory path refused), duplicates and bad arguments refused before anything runs (an empty `passwd` among them), `user=None` the login name with no environment variable read; a `close()` from another thread wakes the consumer (sync and async) at once rather than at the wedged device's budget; a worker thread the system refuses (the pool's first, or one added as the work grows) is the caller's error at once, the run recorded as skipped, no dead thread kept, and the Fleet usable after; the budget of a command that is not a read is one attempt (a batch with one such command too); a close() that catches a run opening its store row waits for the row and records it as interrupted, show() raising `this Fleet is closed`, and a Timer closing the Fleet armed before show(), many rounds a second, never gives a sqlite error or leaves a run row open; `close(wait=)` with devices queued skips them and records the run as interrupted (sync and async, and with every worker held), no FAILED "every worker thread was held" result; a Ctrl-C during close()'s grace still ends the run (the consumer wakes, the run row closed as interrupted); a store-loss warning a filter makes an error is raised and still lets the next run in; two Fleets on one Store from two threads keep every row (never two writers inside one transaction, whatever the scheduler does); a Fleet dropped without close() lets its threads go and brings the pool count back to 0 once collected (one whose device's call raised too), also when the collection runs inside the pool count's lock, and with its last reference, no collector pass, when its run was read to the end with every call returned (sync and async); a refused reaper thread leaves the count at 0 and the pool off; store loss said for every run, not once per process, and no message of it kept for the life of the process; a transport traceback kept off stderr while logging is not set up, and handed to the caller's logging once it is; a store write that raises while close() settles (an 'error' warnings filter) still ends the run |
| test_format.py | 21 | `--format json\|xml` through `rpc()`/`rpc_batch()`, refusal on other transports and on edits, `--json`/`--raw`/`-v`/`--diff` shapes |
| test_generic.py | 45 | the paramiko transport (`hssh/transports/ssh.py`): host keys pinned in `~/.h-ssh/known_hosts` (0600) under a file lock, the known_hosts files parsed once per process and shared until they change (a pin this process adds is in the shared copy), `HSSH_HOST_KEY_POLICY`, changed key refused, parallel first contacts, exit status → failure, reads and the exit status bounded by the command timeout, every phase of the connect (TCP, banner, auth, the shell's channel open) on the session timeout, a reply the CLI refuses at exit 0, the Junos and IOS-shaped dialect edits and confirms on a fake shell channel, EOS `\| json` |
| test_input_validation.py | 34 | #62: wrong input is refused with a named reason before anything runs — numeric flags and config keys out of range, ports, BOM inventories, a `--config` that is not a file, `--save-output` on a file, a closed stdout, whitespace commands, unknown job keys, lines without `=`, wide CSV rows, a target that still says `arista` |
| test_job_pool.py | 4 | #57: a job's entries share one NETCONF session per device |
| test_job.py | 20 | `--job` files and stdin, `default_vendor`, same device twice (entries carried with their results) |
| test_junos.py | 55 | the NETCONF transport (`hssh/transports/netconf.py`) over a fake PyEZ: show, batch, the session close off the caller's clock (a helper thread, `wait_for_closes()` at the end of a run), edit sequence, dry-run, commit-confirmed, the commit edge cases, `rollback()`, `begin()`/`Transaction`, comments, `confirm()` under the lock, `guarded_commit()` and its history check, `expected_diff`, a timer that cannot be armed refused before any session, `statement not found` the one load warning ignored |
| test_openssh_dialects.py | 26 | #83: `junos@openssh`, `ios@openssh`, `nxos@openssh`, `eos@openssh` — shows on an exec like the plain `openssh` driver, edits and confirms through the CLI engine on `ssh -tt`, against a fake `ssh` on PATH |
| test_openssh.py | 27 | the OpenSSH-binary transport, `SSH_ASKPASS`, ControlMaster, `--` before the host, the session clock read from ssh's `-v` log |
| test_output_hygiene.py | 11 | #63: a closed stdout (`\| head`) is not an error, paramiko's transport tracebacks stay off the screen, the confirm reminder prints only for timers that are running, a confirm with nothing pending commits nothing |
| test_packaging.py | 1 | wheel contents: `hssh/`, the dialects' JSON libraries next to them, no top-level `commands/` |
| test_pool.py | 51 | session pool: reuse per `(host, port, user, credential)`, stale detection and probe, discard rules on every edit failure, reopen-once for reads, threads never share a session, reaper, `close_all`, re-entrancy, a nested borrow never closes the session under an open transaction |
| test_profiles.py | 4 | `--profile NAME`: a batch file by name, yours in `~/.h-ssh/profiles` before the shipped `junos-health`/`junos-snapshot`, with or without `.txt`, a path taken as given; run exactly like `--batch`; `--profile` with `--batch` or an unknown name is exit 2; `--list-profiles` lists yours then the shipped ones with their command counts and descriptions |
| test_raw.py | 10 | `--raw` output contract and the JSON output shape |
| test_retry.py | 42 | failure classification (PyEZ connect phase by its prefix, `invalid` narrowed, a rejected command permanent), backoff, the attempt budget, workers clamped and really parallel, edits retried only on `NotAppliedError` |
| test_rpc.py | 19 | `rpc()`: CLI-command translation, RPC name + args, JSON/XML, never re-sending non-reads, `rpc_batch()`, `commit_status()` (pending only on the latest commit) |
| test_runner_edit.py | 33 | runner policy by the driver's `supports`: dry-run and commit-confirmed refusals, retry rule, confirm, rollback mode, comments, commit-status mode, `-eD`/`-eB` load the same lines, no resolver call |
| test_safety.py | 22 | SafetyGate rate limit, cooldown, flock (one yield: an `OSError` in the body propagates), corrupt-file handling |
| test_structured.py | 8 | `--structured` bindings and fallback, the same shortcut resolving per vendor, every shipped binding well-formed, the capability being the registry's and not module attribute presence |
| test_telnet.py | 45 | the telnet transport on a scripted fake server: readers raise on timeout/EOF, failed login detected, silent console gets one Enter, `configure exclusive`, anchored error match, commit outcome unknown, a commit that drops the session still ok, the dry run's diff committed only if it shows again, best-effort cleanup |
| test_store_hardening.py | 8 | the store under load and misfortune: two runs creating one fresh file at the same instant both start (the WAL switch waits out the other's lock, gives up on the clock), `synchronous=NORMAL` and one commit per device result, a store that fails mid-run is said as it happens and counted at the end with exit 4 while every reply is still shown, a store file deleted under the run is detected (exit 4, never a silent 0), a device failure and a store loss both in the summary, the workers hint for a fleet of more than four waves, a store written from another thread than the one that opened it |
| test_store.py | 22 | the result store, always on: `./h-ssh.db` in the current directory unless `--store`, `HSSH_STORE` or `store =` in the config says otherwise (that precedence), `--no-store` keeps nothing, a directory that cannot be written is no run (exit 2, nothing sent), the reader looks where the run wrote; a 0600 file with the two tables, one row per command kept as it came (hashes included: a snapshot to restore from), a batch per command, a commit history as JSON, a retry replacing its row, runs found by id, unique prefix or as the last; run ids sortable by second with four random hex digits, and two runs of one second that drew the same digits still getting different ids (an id the caller chose is not replaced); the `h-ssh-store` reader (runs, failed, output, grep, field, diff, history, slowest, and what it refuses; `export` as CSV or JSON Lines, one run or the whole store, to stdout or a file, with the batch's commands as separate rows); through the CLI: a show run with its run row, a batch, `HSSH_STORE`, an unusable path refusing the run before any device, a dry-run edit's payload and verdict; two threads writing one Store at once keep every row (one write transaction at a time: a writer waiting inside its transaction never meets the other there) |
| test_time_bounds.py | 11 | #66: `--session-timeout` and `--workers` bound everything that touches a device, the pre-flight included; a router that accepts TCP and then says nothing costs the session timeout, not a library default |
| test_transport_consistency.py | 8 | #67: the transports agree on what a password means, an edit's verdict comes from the reply as well as the exit status, a delete of what is not there is not a failure, the open-file limit is checked before it bites |

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
