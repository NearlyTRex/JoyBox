# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def waits(monkeypatch):
    # Replaces selenium's wait so the timeout is never actually spent.
    from webpage_helpers import FakeElement
    ui = pytest.importorskip("selenium.webdriver.support.ui")

    state = {"result": FakeElement(text = "ready"), "error": None, "timeouts": []}

    class FakeWait:
        def __init__(self, driver, timeout):
            state["timeouts"].append(timeout)

        def until(self, condition):
            error = state["error"]
            if error is not None:
                raise error
            return state["result"]

    monkeypatch.setattr(ui, "WebDriverWait", FakeWait)
    return state
