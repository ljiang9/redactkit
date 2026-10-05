"""Enables `python -m redactkit`."""
import sys

if __package__:
    from .redactkit import main
else:
    from redactkit import main

if __name__ == "__main__":
    sys.exit(main())
