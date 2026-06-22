"""Double-click launcher for the SecureLink dashboard.

On Windows, ``.pyw`` files open with ``pythonw.exe``, so the GUI starts with no
console window. From a file manager, double-click this file (or SecureLink.bat,
or the Start Menu / Desktop shortcut). It also works from any directory by
pinning the project root onto the path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

from ui.dashboard import launch_dashboard

if __name__ == "__main__":
    raise SystemExit(launch_dashboard())
