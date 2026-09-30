# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import steam

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def reachable(monkeypatch):
    # Declares which urls answer, so the probing order is observable.
    state = {"ok": set(), "all": False, "probed": []}

    def is_url_reachable(url):
        state["probed"].append(url)
        if state["all"]:
            return True
        return url in state["ok"]

    monkeypatch.setattr(steam.network, "is_url_reachable", is_url_reachable)
    return state


@pytest.fixture
def steam_store(isolated_settings, tmp_path):
    from steam_helpers import STEAM_SETTINGS
    install_dir = tmp_path / "steam"
    install_dir.mkdir()
    for key, value in STEAM_SETTINGS + [("steam_install_dir", str(install_dir))]:
        isolated_settings.set_value("UserData.Steam", key, value)
    return steam.Steam()
