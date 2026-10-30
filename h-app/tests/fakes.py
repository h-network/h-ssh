"""A NETCONF-shaped fake communicator and registry for orchestrator tests; no device needed."""
import asyncio

from hssh.dialects import junos
from hssh.drivers import Driver, Registry
from hssh.model import CommitStatus, Fault, FaultKind, Result, RunSpec, Target
from hssh.orchestrator import execute

T1 = Target("r1", "127.0.0.1", "junos", "netconf")
T2 = Target("r2", "127.0.0.2", "junos", "netconf")


class FakeNetconf:
    default_port = 830
    banner = b"SSH-"
    capabilities = frozenset({"show", "batch", "edit", "commit_confirmed", "confirm", "commit_status"})

    def __init__(self, dialect=junos.DIALECT, *, changed=True, pending=False, open_fault=None, commit_fault=None):
        self.dialect, self.changed, self.pending = dialect, changed, pending
        self.open_fault, self.commit_fault = open_fault, commit_fault
        self.calls: list = []
        self.loaded: dict[str, list[str]] = {}

    def open(self, target, creds, timeouts, policy):
        self.calls.append(("open", target.name))
        if self.open_fault is not None:
            raise self.open_fault
        return {"name": target.name}

    def close(self, session):
        self.calls.append(("close", session["name"]))

    def show(self, session, command):
        self.calls.append(("show", command))
        return Result("output")

    def load(self, session, lines):
        self.calls.append(("load", session["name"]))
        self.loaded.setdefault(session["name"], []).extend(lines)
        return Result("")

    def diff(self, session):
        self.calls.append(("diff", session["name"]))
        return Result("+ change" if self.changed else "", self.changed)

    def commit(self, session, minutes, comment):
        self.calls.append(("commit", minutes, comment))
        if self.commit_fault is not None:
            raise self.commit_fault
        return Result("commit complete")

    def confirm(self, session):
        self.calls.append(("confirm", session["name"]))
        return Result("commit complete")

    def commit_history(self, session):
        self.calls.append(("history", session["name"]))
        return Result("<commit-information/>", CommitStatus(self.pending, 7 if self.pending else None, "<entry/>"))


def registry_for(comm: FakeNetconf) -> Registry:
    return Registry(drivers=[Driver("junos@netconf", comm.dialect, comm)])


def run(spec: RunSpec, comm: FakeNetconf, **kw):
    return asyncio.run(execute(spec, registry_for(comm), **kw))


def fault_of(op) -> Fault:
    assert isinstance(op.outcome, Fault), op
    return op.outcome


__all__ = ["T1", "T2", "FakeNetconf", "FaultKind", "fault_of", "registry_for", "run"]
