from hssh.model import RunReport

STARTED, FINISHED = "2026-10-30T10:00:00+00:00", "2026-10-30T10:00:01.500+00:00"


def report(spec=None, mode="show", results=(), ok=0, failed=0, skipped=0, **fields) -> RunReport:
    return RunReport(1, spec.mode if spec is not None else mode, STARTED, FINISHED, list(results), ok, failed, skipped, **fields)
