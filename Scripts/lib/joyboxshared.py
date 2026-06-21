# Puts the repo-root Shared/ directory on sys.path so the `joybox` shared core
# package is importable. Import this before importing anything from `joybox`.

import os
import sys

_shared_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
if _shared_dir not in sys.path:
    sys.path.append(_shared_dir)
