# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.connection import connection_ssh

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


# The client is shared on the class, so a test that leaves one attached hands
# it to whatever runs next.
@pytest.fixture(autouse = True)
def no_shared_client():
    connection_ssh.ConnectionSSH.ssh_client = None
    yield
    connection_ssh.ConnectionSSH.ssh_client = None
