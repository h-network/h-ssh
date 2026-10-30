# Reading retained runs

`h-ssh-store` reads the versioned SQLite store without changing its schema or results. It
uses the same path as `h-ssh`: `--store`, then `HSSH_STORE`, then the config file's `store`,
then the orchestrator's default `./h-ssh.db`. `~` is expanded. Use `--config FILE` to select
another config; otherwise it reads `~/.h-ssh/config`. An explicitly empty path is an error.
The writer also accepts a run-file setting between its flag and environment value.

```sh
h-ssh-store --store ./h-ssh.db runs --last 10
h-ssh-store failed
h-ssh-store output R1 42 --seq 0
h-ssh-store grep 'Junos' --run 42 --device R1
h-ssh-store field pending --run 42 --command commit_history
h-ssh-store diff R1 41 42 --seq 0
h-ssh-store history R1 --last 20
h-ssh-store slowest 42 --last 10
h-ssh-store export 42 --format csv --out ./run-42.csv
h-ssh-store export --all --format jsonl --out ./results.jsonl
```

| Command | What it reads | Default selection |
|---|---|---|
| `runs` | Run metadata, counts, interruption state, not-kept count and argv | Newest 20 runs |
| `failed [RUN]` | Failed operations belonging to failed targets; skips and close warnings on successful targets are excluded | Latest run |
| `output TARGET [RUN]` | One operation's raw output; a fault is reported on stderr | Latest run, sequence 0 |
| `grep PATTERN` | Matching logical lines in successful outputs; `-i` ignores case | All runs |
| `field PATH` | A dotted path in structured JSON, falling back to raw JSON output when no separate data was kept | All runs |
| `diff TARGET BEFORE AFTER` | A unified diff of successful outputs, compared as logical lines | Sequence 0 |
| `history TARGET` | A target's operations in timestamp order | Newest 50 operations |
| `slowest [RUN]` | Operations ordered by elapsed milliseconds | Slowest 20 across all runs |
| `export [RUN]` | Every stored result column, as CSV or JSONL | Latest run, CSV |

A run selector is its exact decimal ID, or an unambiguous literal decimal prefix. Exact
matches win. Wildcards, empty selectors, missing IDs and ambiguous prefixes are errors.
Omitting a run where the table says "latest" selects by the timestamp's instant, then ID,
not by the local-time text alone. `grep` and `field` select one run with `--run`.

`--device` (also `--target`), `--command` and `--seq` filter `failed`, `grep`, `field`,
`slowest` and `export`. Target and command filters are exact; empty filters are refused.
`history` also accepts `--command` and `--seq`. Sequence numbers start at zero and follow
the target's operation order. `--last` must be positive on the command line. The library
query methods separately accept zero for no rows and None for an unlimited stream.

`field` treats a present JSON null as a value and prints `null`; missing fields do not
match. List indices may be signed decimal integers; malformed or out-of-range indices do
not match. Empty path components are refused. `diff` refuses a missing or failed operand
instead of comparing it as empty output. Line endings and a missing final newline do not
cause a logical-line difference; stored output itself is unchanged.

CSV quotes embedded newlines and includes a header. JSONL writes one result per line and
decodes the separate `data` column into a JSON value; CSV keeps that column's JSON text.
`--all` exports all runs and cannot be combined with a run selector. Export rows stream in
run/target/sequence order. Destination files are private, and the reader refuses the store
or any SQLite sidecar as a destination, including symlink and hard-link aliases, before
truncating. Symlinks and FIFOs are refused; character devices such as `/dev/null` are allowed.

Device output, stored values and exports are left raw in pipes and files. Terminal output
uses the shared terminal filter; table fields are sanitized before shortening. `output`
writes the stored text without adding a newline. If a downstream reader closes a pipe,
the command keeps its known verdict without a traceback.

| Exit | Meaning |
|---|---|
| 0 | Successful read, no failed targets found, identical diff, or a grep/field/export match |
| 1 | Failed output operation, failed targets found, changed diff, or no grep/field/export matches |
| 2 | Invalid arguments, missing selection, incompatible store, failed diff operand, or an I/O/archive error |

A read-only archive is read normally when SQLite can use its sidecars. If the directory is
not writable, the reader uses an immutable view only when no WAL data or journal is pending.
If there is pending data, copy the database with its sidecars to a writable directory and
read it there. An archive changed while being read is reported as incomplete, never as a
trustworthy partial result. Older incompatible stores remain readable with develop's
`h-ssh-store`; the rewrite does not migrate or adapt them.
