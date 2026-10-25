"""What bounds a run on this machine: the worker ceiling, and the open-file
limit that the workers must fit under. The CLI carries the same two for now
(hssh/cli.py); a later cleanup points it here. The library (hssh.fleet)
reads them from here."""

# A thread per in-flight device, so the ceiling is an operator's choice rather
# than a property of the machine. Capped because each one is an ssh process.
MAX_WORKERS = 256


# Descriptors one in-flight device costs: measured at ~6 for a NETCONF
# session (socket, ncclient's selector, paramiko's pipe), the heaviest case.
FDS_PER_WORKER = 6
FDS_BASE = 32


def fit_workers_to_open_files(workers: int):
    """(workers the open-file limit can carry, a note when that is fewer).
    The soft limit is raised towards the hard one first, which needs no
    privilege; only what is still short lowers the workers (L10)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, ValueError, OSError):
        return workers, None
    need = workers * FDS_PER_WORKER + FDS_BASE
    if soft != resource.RLIM_INFINITY and soft < need:
        wanted = need if hard == resource.RLIM_INFINITY else min(need, hard)
        if wanted > soft:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
                soft = wanted
            except (ValueError, OSError):
                pass
    if soft == resource.RLIM_INFINITY or soft >= need:
        return workers, None
    fit = max(1, (soft - FDS_BASE) // FDS_PER_WORKER)
    return fit, (f"the open-file limit of {soft} (ulimit -n) carries {fit} workers at "
                 f"~{FDS_PER_WORKER} descriptors each, not {workers}; running {fit}")
