# h-ssh

Run operational commands and configuration changes across fleets of network devices, from the command line or from Python.

## Why the new build

h-ssh has been rebuilt from scratch. It keeps the features and the hard-won lessons of the previous build, and drops the duplicate code and the overengineering. It is now split into small modules: front ends, one orchestrator that holds all policy, a communicator per transport, vendor dialects, and the records. It is about a third of the code (about 3,000 lines against 9,300) and faster on every path we measure.

Measured on 250 Junos devices over NETCONF, the previous build (`develop` at `3e001d6`) against this one. Each figure is the wall time of the whole run:

| Workload | Previous build | New build | Faster |
|---|---|---|---|
| 3-command batch, 8 workers | 16.4 s | 7.7 s | 2.1× |
| 3-command batch, 50 workers | 4.2 s | 3.2 s | 1.3× |
| The same with 4 unreachable devices, 8 workers | 22.9 s | 10.8 s | 2.1× |
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
- edits: dry run, apply, commit confirmed and confirm, commit status, per-device payload files;
- the result store and the `h-ssh-store` reader;
- the audit log and the safety gate;
- session reuse.

Next: SSH and OpenSSH, then other vendors.

Documentation: [architecture](doc/architecture.md), [testing](doc/testing.md), [result store](doc/store.md), [NETCONF](doc/netconf.md).
