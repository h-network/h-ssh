# Testing

h-ssh is tested at two levels.

| Level | What it proves |
|---|---|
| Continuous integration | The code builds, installs, and passes lint and the unit suite on every supported Python version |
| Fleet testing | h-ssh behaves correctly against real devices, at scale, under real workloads |

Every merge requires both: CI green on the pull request, and a fleet test pass.

## 1. Continuous integration

### 1.1 The workflow

The workflow is defined in `.github/workflows/tests.yml`. It runs on every push to `main` and `develop`,
and on every pull request.

| Job | Runs in | Steps |
|---|---|---|
| `pytest` | `python:3.10`, `3.11`, `3.12` and `3.13` containers | Install with the dev extras: `pip install -e '.[dev]'`. Run the unit suite as an unprivileged user: `python -m pytest -q` |
| `lint` | `python:3.12` | `ruff check --select E9,F63,F7,F82,F821,F823,F811 h-app/hssh h-app/tests`: syntax errors, undefined names, redefinitions |
| `install` | `python:3.12` | A clean `pip install .` into a new venv. The entry point starts. A refused connection with `--no-probe` (and with the default probe) ends as a failed device with exit 1 and no traceback |

Each `pytest` matrix entry runs independently, so one Python version failing does not stop the others.

### 1.2 The unit suite

The unit suite needs no network devices. It tests:

- the orchestrator against a fake communicator: policy, the edit lifecycle, cancellation, recording
- each communicator against the contract in `architecture.md`, section 4, using local fake servers and
  stubbed libraries
- dialect patterns against recorded device output
- the front ends: flags, configuration precedence, exit codes

Each test covers one behaviour.

### 1.3 Running CI locally

Run the same steps as the workflow before every push. From the repository root:

```sh
python -m venv .venv
.venv/bin/pip install -e '.[dev]'

# lint
.venv/bin/pip install ruff
.venv/bin/ruff check --select E9,F63,F7,F82,F821,F823,F811 h-app/hssh h-app/tests

# unit suite
.venv/bin/python -m pytest -q

# install check: a clean install, the entry point, a refused connection reaches the transport and ends as a failed device
python -m venv /tmp/hssh-install && /tmp/hssh-install/bin/pip install -q .
/tmp/hssh-install/bin/h-ssh --help >/dev/null && /tmp/hssh-install/bin/h-ssh --list-profiles >/dev/null
rc=0; /tmp/hssh-install/bin/h-ssh --no-store --no-probe --transport netconf --user u \
    --target x:127.0.0.1:junos --session-timeout 1 --retries 0 -sC "show version" \
    >/tmp/hssh-out 2>/tmp/hssh-err || rc=$?
test "$rc" -eq 1 && grep -q 'x: FAIL open: UNREACHABLE .*Connection refused' /tmp/hssh-out \
    && grep -q '^\[h-ssh\] {' /tmp/hssh-err && ! grep -q Traceback /tmp/hssh-err
```

To match CI's Python versions and unprivileged user exactly, run the suite in the same containers:

```sh
for v in 3.10 3.11 3.12 3.13; do
  docker run --rm -v "$PWD":/src -w /src python:$v \
    sh -c "pip install -q -e '.[dev]' && useradd -m t && runuser -u t -- env HOME=/home/t python -m pytest -q -o cache_dir=/tmp/pytest" || echo "FAILED on $v"
done
```

## 2. Fleet testing

### 2.1 The fleet

Fleet tests run against a fleet of virtual network devices, using the whole fleet.

### 2.2 Workloads

Every fleet pass runs the **standard** group: a three-command batch on every device, at a low and a high
worker count, and with unreachable devices mixed into the target list. A change adds the groups it touches:

| Group | Scope |
|---|---|
| edits | Dry run, apply with a comment, commit confirmed and confirm, commit status, refusals, two runs on one device |
| edits-dir | Per-device payload files, missing files, an interrupted commit |
| store | Stored results against the raw output, concurrent writers, audit log and file permissions, recording failures |
| gate | Cooldown, a held fleet, expiry, local refusals, the login budget |
| reader | Every `h-ssh-store` command, export round trips, read watches |
| pooling | Session reuse across calls on one Fleet |

Waits on commit-confirmed timers run only when a change touches commit-confirmed or confirm behaviour.

Each group runs on the branch under test and on the baseline, `develop`, against the same devices.

### 2.3 Procedure

Every pass runs the same fleet script, with the groups the change touches. The script installs the branch and
the baseline side by side, then:

1. records every device's starting state;
2. runs each workload on both sides;
3. checks each outcome on the devices themselves, not only in h-ssh's report;
4. restores each device and verifies the restore.

The baseline and the branch each use their own installation, result store, audit log and output directory.
Runs are unattended: credentials come from keys or the environment, never from an interactive prompt.

### 2.4 Verdict

A fleet test passes when the change works and does what it is expected to do, on every device in the run.

Each change states what it improves compared with the baseline: speed, or a function or feature. The
report shows that improvement as measured on the fleet, for example run time or the result of the
workload the change affects.

### 2.5 Report

The report is the script's output: one row per check (group, check, side, PASS or FAIL, the key number or
wall time), then the verdict line. One more line only for a failure or something unexpected.
