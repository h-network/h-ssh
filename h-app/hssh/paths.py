import re
from pathlib import Path


_DEVICE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*")


def validate_device_name(name: str) -> str:
    if not _DEVICE_NAME.fullmatch(name):
        raise ValueError(f"invalid device name {name!r}: letters, digits, '_', '.', ':' and '-' only, not starting with '-' or '.'")
    return name


def path_inside(base: Path, filename: str) -> Path:
    if (base.resolve() / filename).resolve().parent != base.resolve():
        raise ValueError(f"{filename!r} does not stay inside {base}")
    return base / filename
