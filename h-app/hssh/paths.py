from pathlib import Path


def validate_device_name(name: str) -> str:
    raise NotImplementedError


def path_inside(base: Path, filename: str) -> Path:
    raise NotImplementedError
