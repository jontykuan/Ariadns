#!/usr/bin/env python
"""Ariadns root entrypoint for SRS Section 5.1 compatibility."""

import sys
from ariadns.interfaces.cli import main

if __name__ == "__main__":
    sys.exit(main())
