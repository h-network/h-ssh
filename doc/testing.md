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
| `pytest` | `python:3.10`, `3.11`, `3.12` and `3.13` containers | Install with the dev extras: `pip install -e '.[dev]'`. Run the unit suite: `python -m pytest -q` |
| `lint` | `python:3.12` | `ruff check --select E9,F63,F7,F82,F821,F823,F811 h-app/hssh h-app/tests`: syntax errors, undefined names, redefinitions |
| `install` | `python:3.12` | A clean `pip install .` into a new venv. Both entry points start. A refused connection ends as a failed device with exit 1 and no traceback. The installer installs and uninstalls |

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

# install check: a clean install, both entry points, a refused connection ends as a failed device
python -m venv /tmp/hssh-install && /tmp/hssh-install/bin/pip install -q .
/tmp/hssh-install/bin/h-ssh --help >/dev/null && /tmp/hssh-install/bin/h-ssh-store --help >/dev/null
rc=0; /tmp/hssh-install/bin/h-ssh --no-store --user u --target x:127.0.0.1:junos --session-timeout 1 \
    --retries 0 -sC "show version" 2>/tmp/hssh-err || rc=$?
test "$rc" -eq 1 && ! grep -q Traceback /tmp/hssh-err

# installer: install from this checkout, then uninstall
git checkout -q -B local-head
H_SSH_REPO="file://$PWD" H_SSH_REF=local-head H_SSH_HOME=/tmp/h-ssh-home H_SSH_BIN=/tmp/h-ssh-bin sh install.sh
H_SSH_HOME=/tmp/h-ssh-home H_SSH_BIN=/tmp/h-ssh-bin sh install.sh --uninstall
```

To match CI's Python versions exactly, run the suite in the same containers:

```sh
for v in 3.10 3.11 3.12 3.13; do
  docker run --rm -v "$PWD":/src -w /src python:$v \
    sh -c "pip install -q -e '.[dev]' && python -m pytest -q" || echo "FAILED on $v"
done
```

## 2. Fleet testing

### 2.1 The fleet

Fleet tests run against a fleet of virtual network devices, using the whole fleet.

### 2.2 Workloads

Fleet tests use real operator workloads, at full fleet scale:

| Workload | Scope |
|---|---|
| Show and batch | Every device, at low and high worker counts, on every transport the fleet supports |
| Edit with diff, dry run | Every device |
| Commit, and commit confirmed followed by confirm | Every device |
| Interrupt | Ctrl-C during a commit run: every commit that landed is recorded |
| Unreachable devices | Dead ports and stopped devices mixed into the target list |
| Records | The store, the audit log, saved output and logs, checked against what the devices report |
| Repeated runs | `--every` over a sustained period |
| Library | The Fleet API running the same workloads as the CLI |

Each test runs on the branch under test and on the baseline, `develop`, against the same devices, so the
results can be compared directly.

### 2.3 Procedure

1. **Record the starting state** of every device the test changes: its running configuration.
2. **Run the workload on the baseline,** and check the outcome on the devices themselves, for example the
   commit history and the configuration, not only in h-ssh's report.
3. **Restore every device** to its starting state, and verify the restore.
4. **Run the workload on the branch,** and check the outcome on the devices in the same way.
5. **Restore every device** again, and verify the restore.
6. **Report** the results with the change.

A device is restored when its running configuration matches the recorded starting configuration. Commit
history entries added by the test remain.

The baseline and branch runs each use their own installation, result store, audit log and output
directory, so every record can be attributed to one run.

Runs are unattended. Credentials come from keys or the environment, never from an interactive prompt.

### 2.4 Verdict

A fleet test passes when the change works and does what it is expected to do, on every device in the run.

Each change states what it improves compared with the baseline: speed, or a function or feature. The
report shows that improvement as measured on the fleet, for example run time or the result of the
workload the change affects.

### 2.5 Report

```
Branch:     <branch> @ <commit>        Baseline: <branch> @ <commit>
Verdict:    PASS | FAIL

Workload            Devices  Branch result            Baseline result
<name>              <n>      <ok/failed/skipped>      <ok/failed/skipped>

Improvement: <speed or function, measured on branch against baseline>
Failures:    <device, what happened, evidence>
Restored:    <yes, how it was verified>
```
