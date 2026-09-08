# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
conftest.py: makes the project root importable so `nse/` is discoverable during
test collection without an install step.
"""

import os
import sys

# Ensure the repository root is always on the path
sys.path.insert(0, os.path.dirname(__file__))
