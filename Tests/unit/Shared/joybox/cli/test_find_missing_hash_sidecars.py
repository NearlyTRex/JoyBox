# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import find_missing_hash_sidecars


###########################################################
# Failed listings
#
# A listing that failed is not an empty one: read as empty, a failed remote
# listing would report no gaps, and a failed sidecar read would report every
# file as missing.
###########################################################

class FakeLockerInfo:

    def __init__(self, locker_type = None):
        pass

    def get_name(self):
        return "hetzner"

    def get_type(self):
        return config.RemoteType.SFTP.val()

    def get_remote_path(self):
        return "/Locker"


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, find_missing_hash_sidecars)
    harness.remote = {"Game.zip": {"hash": "aaaa"}}
    harness.sidecar = {"Game.zip": {"hash": "aaaa"}}
    harness.reported = []
    tool_module = find_missing_hash_sidecars
    monkeypatch.setattr(tool_module.lockerinfo, "LockerInfo", FakeLockerInfo)
    monkeypatch.setattr(tool_module.sync, "is_remote_configured", lambda name, remote_type: True)
    monkeypatch.setattr(tool_module.sync, "list_files_with_hashes", lambda **kwargs: harness.remote)
    monkeypatch.setattr(tool_module.sync, "list_files_with_hashes_from_sidecar", lambda **kwargs: harness.sidecar)
    monkeypatch.setattr(tool_module.reports, "write_list_report", lambda items, **kwargs: harness.reported.extend(items))
    return harness


def test_files_without_a_sidecar_entry_are_reported(tool):
    tool.remote = {"Game.zip": {"hash": "aaaa"}, "New.zip": {"hash": ""}}

    tool.run()

    assert tool.reported == ["New.zip"]


def test_a_failed_remote_listing_exits_with_an_error(tool):
    tool.remote = None

    assert tool.exit_code() != 0
    assert tool.errors == ["Could not list files on hetzner"]
    assert tool.reported == []


def test_a_failed_sidecar_read_exits_with_an_error(tool):
    tool.sidecar = None

    assert tool.exit_code() != 0
    assert tool.errors == ["Could not read the hash sidecar on hetzner"]
    assert tool.reported == []


def test_a_remote_without_a_sidecar_reports_every_file(tool):
    tool.sidecar = {}

    tool.run()

    assert tool.reported == ["Game.zip"]


def test_a_subtree_is_listed_but_looked_up_from_the_locker_root(tool, monkeypatch):
    listed = []
    monkeypatch.setattr(find_missing_hash_sidecars.sync, "list_files_with_hashes",
        lambda **kwargs: listed.append(kwargs["remote_path"]) or {"Game.zip": {}, "New.zip": {}})
    tool.sidecar = {"Gaming/Roms/Game.zip": {}}

    tool.run("--path", "Gaming/Roms")

    assert listed == ["/Locker/Gaming/Roms"]
    assert tool.reported == ["New.zip"]


def test_an_unconfigured_remote_stops_before_listing(tool, monkeypatch):
    monkeypatch.setattr(find_missing_hash_sidecars.sync, "is_remote_configured", lambda name, remote_type: False)

    assert tool.exit_code() != 0
    assert tool.errors == ["Remote 'hetzner' is not configured"]


def test_a_fully_covered_remote_reports_nothing(tool):
    tool.run()

    assert tool.reported == []
    assert tool.errors == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, find_missing_hash_sidecars)
