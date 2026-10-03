# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import llmchat

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def backend():
    from llmchat_helpers import RecordingBackend
    return RecordingBackend()


@pytest.fixture
def session(backend):
    return llmchat.Session(backend, "small")


@pytest.fixture
def chat(session):
    session.seed_context(system_text = "Be terse.")
    return session


@pytest.fixture
def output():
    from llmchat_helpers import Transcript
    return Transcript()
