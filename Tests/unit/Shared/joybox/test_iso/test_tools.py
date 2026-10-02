# Imports
import pytest

# Local imports
from joybox import iso


###########################################################
# Finding the tools
#
# Three tools do the work here, and each is looked up in one place so the
# whole module reports a missing one the same way.
###########################################################

@pytest.mark.parametrize("getter,tool", [
    ("get_iso_tool", "XorrISO"),
    ("get_mount_tool", "FuseISO"),
    ("get_unmount_tool", "FUserMount"),
])
def test_each_tool_is_found_by_its_own_name(monkeypatch, getter, tool):
    asked = []
    monkeypatch.setattr(
        iso.programs, "is_tool_installed", lambda name: asked.append(name) or True)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: "/tools/" + name)

    assert getattr(iso, getter)() == "/tools/" + tool
    assert asked == [tool]


@pytest.mark.parametrize("getter", ["get_iso_tool", "get_mount_tool", "get_unmount_tool"])
def test_a_tool_that_is_not_installed_is_reported(monkeypatch, getter):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: None)

    assert getattr(iso, getter)() is None


def test_the_three_tools_are_distinct(monkeypatch):
    # Mounting and unmounting are different programs, and the packer is a
    # third; one lookup wired to the wrong name fails somewhere unrelated.
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: name)

    found = [iso.get_iso_tool(), iso.get_mount_tool(), iso.get_unmount_tool()]

    assert len(set(found)) == len(found)
