# h-ssh

Run operational commands and configuration changes across fleets of network devices, from the command line or from Python.

## Why the new build

h-ssh has been rebuilt from scratch. It keeps the features and the hard-won lessons of the previous build, and drops the duplicate code and the overengineering. It is now split into small modules: front ends, one orchestrator that holds all policy, a communicator per transport, vendor dialects, and the records. It is about a third of the code (about 3,000 lines against 9,300) and faster on every path we measure.

Measured on 250 Junos devices over NETCONF and SSH, the previous build (`develop` at `3e001d6`) against this one. Each figure is the wall time of the whole run:

| Workload | Previous build | New build | Faster |
|---|---|---|---|
| 3-command batch, 8 workers | 16.4 s | 7.7 s | 2.1× |
| 3-command batch, 50 workers | 4.2 s | 3.2 s | 1.3× |
| The same with 4 unreachable devices, 8 workers | 22.9 s | 10.8 s | 2.1× |
| 3-command batch over SSH, 8 workers | 9.6 s | 9.2 s | 1.0× |
| 3-command batch over SSH, 50 workers | 5.5 s | 2.6 s | 2.1× |
| The same over SSH with 4 unreachable devices, 8 workers | 16.5 s | 12.3 s | 1.3× |
| Edit, dry run | 27.5 s | 8.9 s | 3.1× |
| Edit, apply with a comment | 44.4 s | 26.8 s | 1.7× |
| Confirm a commit-confirmed | 45.7 s | 11.6 s | 3.9× |
| Commit status | 17.0 s | 4.3 s | 4.0× |
| Three calls on one Python `Fleet`, 8 workers | 18.3 s | 8.0 s | 2.3× |
| Three calls on one Python `Fleet`, 50 workers | 12.5 s | 3.2 s | 3.9× |

A `Fleet` keeps one session per device across its calls. Three calls cost 250 logins instead of 750, and take 2.2–2.5× less time than three separate runs.

## Status

Built, on `junos@netconf`:
- shows and batches;
- edits: dry run, apply, commit confirmed and confirm (`--synchronize` for dual routing engines, NETCONF only),
  commit status, per-device payload files;
- the result store and the `h-ssh-store` reader;
- the audit log and the safety gate;
- session reuse.

On `junos@ssh`: shows and batches.

Next: edits over SSH, then OpenSSH, then other vendors.

## From Python

```python
from hssh.frontends.fleet import Fleet

with Fleet(["10.0.1.1", "cr2:10.0.1.2:junos"], transport="netconf", user="admin", password="…") as fleet:
    report = fleet.show("show bgp summary")                 # one login per device, kept for the next call
    report = fleet.batch(["show version", "show route summary"])
    report = fleet.structured("show interfaces terse", "json")   # the reply as data, NETCONF only
    report = fleet.edit(["set system host-name cr1"], apply=True, confirmed_minutes=5, synchronize=True)
    report = fleet.confirm(synchronize=True)                 # commit synchronize on both; NETCONF only
    for result in report.results:
        for op in result.operations:
            print(result.target.name, op.command, op.outcome)
```

`Fleet.structured(command, fmt)` is the library's alone: `fmt` is `json` or `xml`, and `Result.data`
carries the parsed reply. The CLI has no `--format`; its reads return the device's text.

Documentation: [architecture](doc/architecture.md), [testing](doc/testing.md), [result store](doc/store.md), [NETCONF](doc/netconf.md).
