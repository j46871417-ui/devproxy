#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevProxy 2.0.0
Universal IDE & Dev Tools Proxy Connection Manager.
"""

import sys
import os

# Ensure package root is in sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from devproxy_pkg.cli import main

if __name__ == "__main__":
    main()
