# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.stores import legacy

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def legacy_store(isolated_settings, tmp_path):
    install_dir = tmp_path / "legacy"
    install_dir.mkdir()
    isolated_settings.set_value("UserData.Legacy", "legacy_username", "player")
    isolated_settings.set_value("UserData.Legacy", "legacy_install_dir", str(install_dir))
    return legacy.Legacy()


@pytest.fixture
def tools(monkeypatch):
    installed = {"PythonVenvPython": "/tools/python", "Heirloom": "/tools/heirloom"}
    monkeypatch.setattr(legacy.programs, "is_tool_installed", lambda name: name in installed)
    monkeypatch.setattr(legacy.programs, "get_tool_program", lambda name: installed.get(name))
    return installed


@pytest.fixture
def no_manifest(monkeypatch):
    class EmptyManifest:
        def find_entry_by_name(self, **kwargs):
            return None
    monkeypatch.setattr(legacy.storebase.manifest, "get_manifest_instance", lambda: EmptyManifest())


@pytest.fixture
def browser(legacy_store, monkeypatch):
    from legacy_helpers import FakeBrowser
    fake = FakeBrowser()

    def web_connect(headless = False, **kwargs):
        return fake.connect(headless)

    def web_disconnect(web_driver, **kwargs):
        fake.disconnected.append((web_driver, kwargs.get("pretend_run")))
        return True

    def load_url(driver, url, **kwargs):
        return fake.load(url)

    def wait_for_element(driver, locator, wait_time = 15, **kwargs):
        fake.waits.append(wait_time)
        return legacy.webpage.get_element(parent = driver, locator = locator)

    monkeypatch.setattr(legacy_store, "web_connect", web_connect)
    monkeypatch.setattr(legacy_store, "web_disconnect", web_disconnect)
    monkeypatch.setattr(legacy.webpage, "load_url", load_url)
    monkeypatch.setattr(legacy.webpage, "wait_for_element", wait_for_element)
    monkeypatch.setattr(legacy.datautils.time, "sleep", lambda seconds: fake.slept.append(seconds))
    return fake
