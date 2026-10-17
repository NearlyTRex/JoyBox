# Imports
import os
import sys
import types
import pytest

# Local imports
from joybox import network

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


###########################################################
# Github
###########################################################

@pytest.fixture
def github(monkeypatch):
    from network_helpers import FakeUser
    state = {"repos": [], "login": "testuser", "token": None}

    class FakeGithub:
        def __init__(self, token = None):
            state["token"] = token

        def get_user(self):
            return FakeUser(state["login"], state["repos"])

    module = types.ModuleType("github")
    module.Github = FakeGithub
    monkeypatch.setitem(sys.modules, "github", module)
    return state


###########################################################
# Requests
###########################################################

@pytest.fixture
def requests_module(monkeypatch):
    # A stand-in for requests, so the behaviour of each wrapper can be driven
    # without reaching the network.
    from network_helpers import FakeResponse
    state = {"response": FakeResponse(), "error": None, "calls": []}

    def record(method):
        def run(url, headers = None, timeout = None, json = None, params = None):
            state["calls"].append({
                "method": method,
                "url": url,
                "params": params,
                "headers": headers,
                "timeout": timeout,
                "json": json,
            })
            error = state["error"]
            if error is not None:
                raise error
            return state["response"]
        return run

    module = types.ModuleType("requests")
    module.get = record("get")
    module.post = record("post")
    monkeypatch.setitem(sys.modules, "requests", module)
    return state


###########################################################
# Tools
###########################################################

@pytest.fixture
def installed(monkeypatch):
    from network_helpers import TOOL_PATHS
    monkeypatch.setattr(network.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(network.programs, "get_tool_program", TOOL_PATHS.get)
    return TOOL_PATHS


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(network.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(network.programs, "get_tool_program", lambda name: None)
