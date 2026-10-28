"""What bounds a run on this machine: the worker ceiling, the probe's, and
the open-file limit that both must fit under, with the sessions the session
pool keeps open. The CLI (hssh.cli) and the library engine (hssh.fleet) both
read them from here, and the pool (hssh.pool) keeps to the same count."""

from typing import Optional

# A thread per in-flight device, so the ceiling is an operator's choice rather
# than a property of the machine. Capped because each one is an ssh process.
MAX_WORKERS = 256

# The probe before a run (#127, hssh.probe) runs at most this many boxes at
# once, whatever --workers says: a TCP connect and a line read each.
MAX_PROBES = 100


# Descriptors one in-flight device costs: measured at ~6 for a NETCONF
# session (socket, ncclient's selector, paramiko's pipe), the heaviest case.
# A probe holds its socket and nothing else. A session the pool keeps open
# between calls holds four: its socket, paramiko's pipe pair and ncclient's
# epoll (#147).
FDS_PER_WORKER = 6
FDS_PER_PROBE = 1
FDS_PER_SESSION = 4
FDS_BASE = 32


def open_file_limit() -> Optional[int]:
    """The process's soft open-file limit now (ulimit -n); None when there is
    none to keep to (unlimited, or no `resource` module on this system)."""
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):
        return None
    return None if soft == resource.RLIM_INFINITY else soft


def _fit(count: int, per: int, beside: int = 0):
    """(how many of `count`, at `per` descriptors each, the open-file limit
    carries, that limit). The soft limit is raised towards the hard one
    first, for them and `beside` descriptors more, which needs no
    privilege; only what is still short of the count alone lowers it (L10).
    The limit is None when it carries them all, `beside` too."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):
        return count, None
    need = count * per + beside + FDS_BASE
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
    return min(count, max(1, (soft - FDS_BASE) // per)), soft


def fit_workers_to_open_files(workers: int, pooled: int = 0):
    """(workers the open-file limit can carry, a note when that is fewer or
    when it cannot hold the pooled sessions too). `pooled`: the sessions
    the session pool keeps open beside the workers (a Fleet's junos
    devices, a job's junos devices with an entry after their first),
    FDS_PER_SESSION each, which the soft limit is raised for too (#147).
    What even the hard limit cannot hold of them lowers no workers: the
    pool keeps what fits, and closes its least recently used idle session
    before it opens another (hssh.pool)."""
    fit, soft = _fit(workers, FDS_PER_WORKER, pooled * FDS_PER_SESSION)
    if soft is None:
        return workers, None
    room = max(0, (soft - FDS_BASE - fit * FDS_PER_WORKER) // FDS_PER_SESSION)
    kept = (f"{room} of the {pooled} pooled sessions open at ~{FDS_PER_SESSION} descriptors each: the least "
            "recently used idle one is closed when another must open, and opened again when it is wanted")
    if fit < workers:
        note = (f"the open-file limit of {soft} (ulimit -n) carries {fit} workers at "
                f"~{FDS_PER_WORKER} descriptors each, not {workers}; running {fit}")
        return fit, note + (f", and it keeps {kept}" if pooled > room else "")
    return fit, f"the open-file limit of {soft} (ulimit -n) keeps {kept}"


def fit_probes_to_open_files(probes: int = MAX_PROBES):
    """(probes the open-file limit can carry at once, a note when that is
    fewer), fitted as the workers are."""
    fit, soft = _fit(probes, FDS_PER_PROBE)
    if soft is None:
        return probes, None
    return fit, (f"the open-file limit of {soft} (ulimit -n) carries {fit} probes at once, not {probes}; "
                 f"probing {fit} at a time")
