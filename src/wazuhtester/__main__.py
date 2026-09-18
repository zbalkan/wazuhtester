"""Allow ``python -m wazuhtester`` to run the command-line interface."""

from wazuhtester.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
