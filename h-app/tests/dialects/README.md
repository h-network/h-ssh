# Dialect unit tests

Run `python -m pytest -q h-app/tests/dialects` from the repository root. These tests use local strings
and the audit redactor; they open no device sessions. At rewrite base `97e4125`, 407 dialect cases pass
and the complete `python -m pytest -q h-app/tests` run passes 411 cases.

- `test_edit.py` covers each vendor's comments and empty-payload refusal, the ten lowercase Junos verbs,
  commit abbreviations and semicolons, controls, Tab, line numbers, inline hashes and unchanged input.
- `test_patterns.py` covers prompt shapes, refusal lines, IOS warnings and syslog exclusions, read rules,
  and the configuration commands that distinguish Junos's candidate from IOS-style configuration.
- `test_redaction.py` exercises dialect patterns through the audit redactor: retained type words and
  markers, escaped quotes, key-line boundaries, XML names, JSON key snippets, scalar fragments and whole
  secret values. Expected strings check group 1 and group 3 preservation as well as removal of secrets.

Sources are develop `3e001d6`: `h-app/tests/dialects/test_dialects.py` (prompt/refusal/warning and comment
cases), `h-app/tests/transports/test_cli.py` (commit/control payloads and RSA/VLAN output notes), and
`h-app/tests/test_audit.py` (`LEAKED_FORMS`, the applicable `LEAKED_TOO` cases, and XML/JSON/value-boundary
checks from #42 and #151). The edit and JSON-key cases also preserve the local checks from the edit-guard
and redaction work. Device-output strings come from those tests; this backfill made no new captures.

Left out:

- CLI comment quoting, newest-entry pending text parsing, prompt learning, paging, channel I/O and
  configuration execution: `CliEngine` still has no implementation for these. The constructor only
  retains its arguments. The `Dialect` and `Channel` protocols have no runtime behaviour to exercise.
- Comment validation and XML commit-history parsing belong to orchestrator and NETCONF respectively.
- Old standalone-commit acceptance, `allow_commit`, tuple guard results, positional dialect construction,
  compatibility exports and rollback operations do not describe the new contract.
- Shortcut libraries and vendor paging commands are not built yet. IOS-specific SNMP host/user and WPA
  redaction patterns remain deferred; shared credential forms are tested on generic and Junos.
- Device transcripts formerly used to test retries, transport ownership, CLI flags and audit-file writes
  stay with their owners. These tests cover the dialect data those operations consume.

Failure sensitivity was checked in separate Python processes with in-memory mutations, leaving the
checkout untouched. Each process ran only the named test against the deliberately broken behaviour:

| Mutation | Test | Result |
|---|---|---|
| Generic `check_edit` always returns `None` | `test_empty_or_comment_only_edit_is_refused` | 20 failed |
| Junos `_CONTROL` matches nothing | `test_junos_refuses_control_characters_and_surrogates` | 10 failed |
| Remove Junos's first redaction pattern | `test_junos_secret_data_keeps_statement_and_marker` | 1 failed, 4 passed |
| IOS refusal pattern accepts every line starting with `%` | `test_ios_syslog_and_ordinary_output_are_not_refusals` | 15 failed, 9 passed |

The unmodified full suite passed after these mutation runs.
