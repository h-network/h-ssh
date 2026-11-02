"""`python3 -m hssh` is the h-ssh command line; `python3 -m hssh store …` is h-ssh-store. The same from hssh.pyz."""

import sys


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "store":
        del sys.argv[1]
        from hssh.frontends.store import main_sync
    else:
        from hssh.frontends.cli import main_sync
    main_sync()


if __name__ == "__main__":
    main()
