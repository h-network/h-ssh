# Test Results

Tested against 3 live Junos vMX routers running 24.2R1-S2.5.

## Unit Tests — 65/65 passed

| Suite | Tests | Status |
|-------|-------|--------|
| test_core.py | 8 | Pass |
| test_safety.py | 12 | Pass |
| test_job.py | 11 | Pass |
| test_telnet.py | 6 | Pass |
| test_structured.py | 9 | Pass |
| test_openssh.py | 19 | Pass |

## Live Integration Tests — 59/59 passed

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
