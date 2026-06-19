# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
conftest.py: makes the project root importable so that both `nse/` and `gui/`
are discoverable during test collection without needing to install `gui/` as a
package.
"""

import sys
import os

# Ensure the repository root is always on the path
sys.path.insert(0, os.path.dirname(__file__))
