# Testing

h-ssh is tested at two levels, each with its own owner.

| Level | What it proves |
|---|---|
| Continuous integration | The code builds, installs, and passes lint and the unit suite on every supported Python version |
| Fleet testing | h-ssh behaves correctly against real devices, at scale, under real workloads |

A change is ready to merge when CI is green on its pull request, and a fleet test pass is reported for
the behaviour it changes.

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

# install check
python -m venv /tmp/hssh-install && /tmp/hssh-install/bin/pip install -q .
/tmp/hssh-install/bin/h-ssh --help >/dev/null && /tmp/hssh-install/bin/h-ssh-store --help >/dev/null
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

The test fleet is a set of Junos cRPD containers reserved for h-ssh testing. Fleet tests use all of it.

### 2.2 What the tester runs

Fleet tests use real operator workloads, at full fleet scale:

| Workload | Scope |
|---|---|
| Show and batch | Every device, at low and high worker counts, on every transport the fleet supports |
| Edit with diff, dry run | Every device |
| Commit, and commit confirmed followed by confirm | Every device |
| Rollback | Every device |
| Interrupt | Ctrl-C during a commit run: every commit that landed is recorded |
| Unreachable devices | Dead ports and stopped devices mixed into the target list |
| Records | The store, the audit log, saved output and logs, checked against what the devices report |
| Repeated runs | `--every` over a sustained period |
| Library | The Fleet API running the same workloads as the CLI |

Each test runs on the branch under test and on the baseline branch, against the same devices, so the
results can be compared directly.

### 2.3 Procedure

1. **Record the starting state** of every device the test changes.
2. **Run the workload** on the baseline, then on the branch.
3. **Check the outcome on the devices themselves,** for example the commit history and the configuration,
   not only in h-ssh's report.
4. **Restore every device** to its starting state, and verify the restore.
5. **Report** the results with the change.

Runs are unattended. Credentials come from keys or the environment, never from an interactive prompt.

### 2.4 Report

```
Branch:     <branch> @ <commit>        Baseline: <branch> @ <commit>
Verdict:    PASS | FAIL

Workload            Devices  Branch result            Baseline result
<name>              <n>      <ok/failed/skipped>      <ok/failed/skipped>

Failures:   <device, what happened, evidence>
Restored:   <yes, how it was verified>
```
