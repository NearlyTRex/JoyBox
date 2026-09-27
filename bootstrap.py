#!/usr/bin/env python3

# Imports
import os
import sys

# Runs with the system python on a fresh machine, before any venv exists, so
# it puts Shared on the path itself
def main():
    sys.path.append(os.path.realpath(os.path.join(os.path.dirname(__file__), "Shared")))
    from joybox.bootstrap import cli
    cli.main()

# Start
if __name__ == "__main__":
    main()
