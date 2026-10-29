"""The orchestrator: executes a RunSpec through drivers and owns all policy (section 3.2)."""

from hssh.orchestrator.scheduler import execute

__all__ = ["execute"]
