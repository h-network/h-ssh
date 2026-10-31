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

## Install

```sh
pip install .
```

That is all: PyEZ (`junos-eznc`) is a required dependency, so there is no `[junos]` extra to ask for. The
commands are `h-ssh` and `h-ssh-store`.

## Status

Built, on `junos@netconf`, `junos@ssh` and `junos@openssh`:
- shows and batches;
- edits on all three transports, SSH and OpenSSH included: dry run, apply, commit confirmed and confirm
  (`--synchronize` for dual routing engines, NETCONF only), commit status, per-device payload files;
- the result store and the `h-ssh-store` reader;
- the audit log and the safety gate;
- session reuse.

Next: other vendors.

## From Python

```python
from hssh.frontends.fleet import Fleet

with Fleet(["10.0.1.1", "cr2:10.0.1.2:junos"], transport="netconf", user="admin", password="…",
           label="pre-upgrade") as fleet:                    # the label is kept with every run, for h-ssh-store
    dead = {name for name, fault in fleet.reachable().items() if fault}   # a TCP connect per device, no login
    report = fleet.show("show bgp summary")                 # one login per device, kept for the next call
    report = fleet.config("xml")                            # the whole committed configuration, as returned; NETCONF only
    report = fleet.batch(["show version", "show route summary"])
    report = fleet.structured("show interfaces terse", "json")   # the reply in json, as returned; NETCONF only
    report = fleet.structured(["show version", "show interfaces terse"], "xml")   # one reply per command
    report = fleet.show({"10.0.1.1": "show version", "cr2": "show chassis hardware"})   # a command per target
    report = fleet.edit(["set system host-name cr1"], apply=True, confirmed_minutes=5, synchronize=True)
    report = fleet.confirm(synchronize=True)                 # commit synchronize on both; NETCONF only
    for result in report.results:
        for op in result.operations:
            print(result.target.name, op.command, op.outcome)
```

`Fleet.structured(command, fmt)` is the library's alone: `fmt` is `json` or `xml`, and `Result.output` holds
the reply as the device returned it, nothing parsed (`Result.data` stays None). The CLI has no `--format`; its reads return the device's text.
`show`, `batch` and `structured` take one command (or list) for every device, or a mapping of device name to
its own command or list; a device not in the mapping is skipped, in one run with one reply per command.
`Fleet(label=…)`, or `--label TEXT` and the run file's `label` key on the CLI, tags the run with free text that
`h-ssh-store` lists and selects by. `reachable(timeout=None)` returns `{name: None or Fault}` without logging in (a device that cannot be probed is absent);
a run that recorded nothing (no store) has `run_id` None, shown as "no run" in text and `null` in `--json`.

Documentation: [architecture](doc/architecture.md), [testing](doc/testing.md), [result store](doc/store.md), [NETCONF](doc/netconf.md).
