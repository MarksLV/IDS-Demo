import sys

from ids.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["gui", *sys.argv[1:]]))
