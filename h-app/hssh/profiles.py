"""Named command sets. A profile is a batch file known by name: your own in
~/.h-ssh/profiles/NAME.txt, or one that ships with h-ssh (hssh/profiles/).
Same format as --batch: one show command per line, `#` comments; a first
comment line is the description --list-profiles shows.

    h-ssh --profile junos-health 10.0.1.1 10.0.1.2
    h-ssh --list-profiles
"""
from pathlib import Path
from typing import List, Optional, Tuple

from .core import read_failure

SHIPPED_DIR = Path(__file__).parent / "profiles"


def user_dir() -> Path:
    return Path.home() / ".h-ssh" / "profiles"


def profile_path(name: str) -> Path:
    """The file behind a profile name: yours first, then the shipped one. A
    name with a slash is a path and taken as given, like --batch."""
    if "/" in name:
        path = Path(name).expanduser()
        if not path.is_file():
            raise ValueError(f"profile {name!r}: no such file")
        return path
    for candidate in (user_dir() / f"{name}.txt", user_dir() / name, SHIPPED_DIR / f"{name}.txt"):
        if candidate.is_file():
            return candidate
    shipped = ", ".join(n for n, _, _, _ in listing()) or "none"
    raise ValueError(f"no profile {name!r}: not in {user_dir()} and not shipped (have: {shipped}); "
                     f"a profile is a batch file, one command per line")


def describe(path: Path) -> Tuple[Optional[int], str]:
    """(number of commands, the description): the first `#` line, or the first
    command. A file that cannot be read (not UTF-8, no permission) is
    (None, why), so the listing still comes out and says so."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        return None, read_failure(e)
    lines = [ln.strip() for ln in text.splitlines()]
    commands = [ln for ln in lines if ln and not ln.startswith("#")]
    comments = [ln.lstrip("#").strip() for ln in lines if ln.startswith("#")]
    return len(commands), (comments[0] if comments else (commands[0] if commands else ""))


def listing() -> List[Tuple[str, str, Optional[int], str]]:
    """(name, origin, commands, description) for every profile, yours before the shipped ones;
    a shipped name you also have is listed once, as yours. A file that cannot be read has
    None for its commands and the reason as its description."""
    seen, out = set(), []
    for origin, directory in (("yours", user_dir()), ("shipped", SHIPPED_DIR)):
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            name = path.name[:-4] if path.name.endswith(".txt") else path.name
            if name in seen:
                continue
            seen.add(name)
            count, text = describe(path)
            out.append((name, origin, count, text))
    return out


def listing_lines() -> List[str]:
    rows = listing()
    if not rows:
        return [f"no profiles: put a batch file in {user_dir()}/NAME.txt"]
    width = max(len(n) for n, _, _, _ in rows)
    lines = []
    for origin in ("yours", "shipped"):
        group = [r for r in rows if r[1] == origin]
        if not group:
            continue
        lines.append(f"{origin} ({user_dir() if origin == 'yours' else SHIPPED_DIR}):")
        lines.extend(f"  {n:<{width}}  {c:>3} commands  {d}" if c is not None
                     else f"  {n:<{width}}  {'unreadable':>12}  {d}" for n, _, c, d in group)
    return lines
