"""What bounds a run on this machine: the worker ceiling, the probe's, and
the open-file limit that both must fit under. The CLI (hssh.cli) and the
library engine (hssh.fleet) both read them from here."""

# A thread per in-flight device, so the ceiling is an operator's choice rather
# than a property of the machine. Capped because each one is an ssh process.
MAX_WORKERS = 256

# The probe before a run (#127, hssh.probe) runs at most this many boxes at
# once, whatever --workers says: a TCP connect and a line read each.
MAX_PROBES = 100


# Descriptors one in-flight device costs: measured at ~6 for a NETCONF
# session (socket, ncclient's selector, paramiko's pipe), the heaviest case.
# A probe holds its socket and nothing else.
FDS_PER_WORKER = 6
FDS_PER_PROBE = 1
FDS_BASE = 32


def _fit(count: int, per: int):
    """(how many of `count`, at `per` descriptors each, the open-file limit
    carries, that limit). The soft limit is raised towards the hard one
    first, which needs no privilege; only what is still short lowers the
    count (L10). The limit is None when it carries them all."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):
        return count, None
    need = count * per + FDS_BASE
    if soft != resource.RLIM_INFINITY and soft < need:
        wanted = need if hard == resource.RLIM_INFINITY else min(need, hard)
        if wanted > soft:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
                soft = wanted
            except (ValueError, OSError):
                pass
    if soft == resource.RLIM_INFINITY or soft >= need:
        return count, None
    return max(1, (soft - FDS_BASE) // per), soft


def fit_workers_to_open_files(workers: int):
    """(workers the open-file limit can carry, a note when that is fewer)."""
    fit, soft = _fit(workers, FDS_PER_WORKER)
    if soft is None:
        return workers, None
    return fit, (f"the open-file limit of {soft} (ulimit -n) carries {fit} workers at "
                 f"~{FDS_PER_WORKER} descriptors each, not {workers}; running {fit}")


def fit_probes_to_open_files(probes: int = MAX_PROBES):
    """(probes the open-file limit can carry at once, a note when that is
    fewer), fitted as the workers are."""
    fit, soft = _fit(probes, FDS_PER_PROBE)
    if soft is None:
        return probes, None
    return fit, (f"the open-file limit of {soft} (ulimit -n) carries {fit} probes at once, not {probes}; "
                 f"probing {fit} at a time")
