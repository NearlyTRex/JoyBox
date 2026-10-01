# Imports
import os
import sys
import types

# Third-party imports
import pytest

# Local imports
from joybox import webpage

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
            if state["error"]:
                raise state["error"]
            return state["result"]

    monkeypatch.setattr(ui, "WebDriverWait", FakeWait)
    return state


@pytest.fixture
def fetches(monkeypatch):
    # The driver path and a stand-in requests module, each scriptable.
    from webpage_helpers import FakeDriver
    state = {"driver": FakeDriver(), "source": "<html>driver</html>",
             "source_error": None, "text": "<html>requests</html>", "status": 200,
             "error": None, "destroyed": [], "requests": []}

    def get_page_source(**kwargs):
        if state["source_error"]:
            raise state["source_error"]
        return state["source"]

    monkeypatch.setattr(webpage, "create_web_driver", lambda **kwargs: state["driver"])
    monkeypatch.setattr(webpage, "get_page_source", get_page_source)
    monkeypatch.setattr(
        webpage, "destroy_web_driver",
        lambda driver, **kwargs: state["destroyed"].append(driver))

    def raise_for_status():
        if state["status"] >= 400:
            raise RuntimeError("HTTP %d" % state["status"])

    def get(url, params = None, timeout = None):
        state["requests"].append({"url": url, "params": params, "timeout": timeout})
        if state["error"]:
            raise state["error"]
        return types.SimpleNamespace(
            text = state["text"], status_code = state["status"],
            raise_for_status = raise_for_status)

    module = types.ModuleType("requests")
    module.get = get
    monkeypatch.setitem(sys.modules, "requests", module)
    return state


@pytest.fixture
def page(monkeypatch):
    state = {"html": "", "calls": []}

    def get_website_text(**kwargs):
        state["calls"].append(kwargs)
        return state["html"]

    monkeypatch.setattr(webpage, "get_website_text", get_website_text)
    return state
