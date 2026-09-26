# Imports
import os
import sys

# Helpers beside this file are imported by name. Appended rather than
# inserted, so this directory's conftest does not shadow the suite's.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)
