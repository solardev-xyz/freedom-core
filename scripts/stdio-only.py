#!/usr/bin/env python3
"""Runs a command with stdio alone: every descriptor above stderr closed.

Main spawns each service with stdio alone, and confinement refuses any
other descriptor (design 0010, "The recommendation", step 1). GitHub's Linux
runners leak a pipe into every step, which each test process, and every
service it spawns, would inherit. The tests that confine run under this, as
a service runs under main.

usage: python3 scripts/stdio-only.py <command> [<arg> ...]
"""

import os
import sys


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__.strip().splitlines()[-1])
    table = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
    for name in os.listdir(table):
        fd = int(name)
        if fd > 2:
            try:
                os.close(fd)
            except OSError:
                # The listing's own descriptor, already closed.
                pass
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
