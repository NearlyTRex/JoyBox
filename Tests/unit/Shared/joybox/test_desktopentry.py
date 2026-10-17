# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import desktopentry


###########################################################
# Desktop entries
#
# A launcher is in the app menu exactly while its tool's role wants it there,
# so configuring a tool on a machine that gave the role up removes it again.
###########################################################

LAUNCHER = {
    "filename": "joybox-thing.desktop",
    "name": "Thing",
    "description": "Does a thing",
    "command": "launch_thing",
    "icon": "input-gaming",
}


@pytest.fixture
def linux(monkeypatch, isolated_settings):
    monkeypatch.setattr(desktopentry.platform_info, "is_linux_platform", lambda: True)


def launcher_path():
    return os.path.join(os.path.expanduser("~"), ".local", "share", "applications", "joybox-thing.desktop")


def test_an_entry_runs_the_joybox_command(isolated_settings):
    lines = desktopentry.build_desktop_entry("Thing", "Does a thing", "launch_thing", ["Extra=1"]).splitlines()

    assert lines[:4] == ["[Desktop Entry]", "Type=Application", "Name=Thing", "Comment=Does a thing"]
    assert lines[4].startswith("Exec=") and lines[4].endswith(os.path.join("bin", "launch_thing"))
    assert lines[5:] == ["Extra=1"]


def test_an_enabled_launcher_is_written_with_its_icon(linux):
    assert desktopentry.set_launcher(True, **LAUNCHER)

    with open(launcher_path(), encoding = "utf-8") as handle:
        text = handle.read()
    assert "Icon=input-gaming\n" in text and "Categories=Game;\n" in text and "Terminal=false\n" in text


def test_a_disabled_launcher_is_removed(linux):
    assert desktopentry.set_launcher(True, **LAUNCHER)

    assert desktopentry.set_launcher(False, **LAUNCHER)

    assert not os.path.exists(launcher_path())


def test_a_disabled_launcher_that_was_never_written_needs_nothing(linux, monkeypatch):
    removed = []
    monkeypatch.setattr(desktopentry.fileops, "remove_file", lambda **kwargs: removed.append(kwargs) or True)

    assert desktopentry.set_launcher(False, **{**LAUNCHER, "filename": "joybox-never-written.desktop"})

    assert removed == []


def test_other_desktops_get_no_launcher(monkeypatch, isolated_settings):
    monkeypatch.setattr(desktopentry.platform_info, "is_linux_platform", lambda: False)

    assert desktopentry.set_launcher(True, **LAUNCHER)

    assert not os.path.exists(launcher_path())
