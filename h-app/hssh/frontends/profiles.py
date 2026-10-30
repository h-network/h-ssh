"""Named command sets: a batch file known by name, yours in ~/.h-ssh/profiles/NAME.txt or shipped."""

from __future__ import annotations

from pathlib import Path

SHIPPED_DIR = Path(__file__).parent / "profiles"


def user_dir() -> Path:
    return Path.home() / ".h-ssh" / "profiles"


def profile_path(name: str) -> Path:
    """Yours first, then the shipped one; a name with a slash is a path taken as given."""
    if "/" in name:
        path = Path(name).expanduser()
        if not path.is_file():
            raise ValueError(f"profile {name!r}: no such file")
        return path
    for candidate in (user_dir() / f"{name}.txt", user_dir() / name, SHIPPED_DIR / f"{name}.txt"):
        if candidate.is_file():
            return candidate
    raise ValueError(f"no profile {name!r}: not in {user_dir()} and not shipped")


def read_commands(path: Path) -> list[str]:
    """One command per line; blank lines and `#` comments dropped."""
    out = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def describe(path: Path) -> tuple[int, str]:
    """(number of commands, description): the first `#` line, else the first command."""
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8-sig").splitlines()]
    commands = [ln for ln in lines if ln and not ln.startswith("#")]
    comments = [ln.lstrip("#").strip() for ln in lines if ln.startswith("#")]
    return len(commands), (comments[0] if comments else (commands[0] if commands else ""))


def listing() -> list[tuple[str, str, int, str]]:
    """(name, origin, commands, description) per profile, yours before shipped; a shipped name you also have is listed once."""
    seen: set[str] = set()
    out = []
    for origin, directory in (("yours", user_dir()), ("shipped", SHIPPED_DIR)):
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.name.startswith(".") or not path.is_file():
                continue
            name = path.name[:-4] if path.name.endswith(".txt") else path.name
            if name in seen:
                continue
            seen.add(name)
            count, text = describe(path)
            out.append((name, origin, count, text))
    return out


def listing_lines() -> list[str]:
    rows = listing()
    if not rows:
        return [f"no profiles: put a batch file in {user_dir()}/NAME.txt"]
    width = max(len(name) for name, _, _, _ in rows)
    lines = []
    for origin in ("yours", "shipped"):
        group = [r for r in rows if r[1] == origin]
        if group:
            lines.append(f"{origin} ({user_dir() if origin == 'yours' else SHIPPED_DIR}):")
            lines.extend(f"  {n:<{width}}  {c:>3} commands  {d}" for n, _, c, d in group)
    return lines
