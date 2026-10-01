# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, system
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
    state = {"remote": {"Game.zip": {"hash": "aaaa"}}, "sidecar": {"Game.zip": {"hash": "aaaa"}},
             "reported": [], "errors": []}
    tool_module = find_missing_hash_sidecars
    monkeypatch.setattr(tool_module.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(tool_module.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(tool_module.lockerinfo, "LockerInfo", FakeLockerInfo)
    monkeypatch.setattr(tool_module.sync, "is_remote_configured", lambda name, remote_type: True)
    monkeypatch.setattr(tool_module.sync, "list_files_with_hashes", lambda **kwargs: state["remote"])
    monkeypatch.setattr(tool_module.sync, "list_files_with_hashes_from_sidecar", lambda **kwargs: state["sidecar"])
    monkeypatch.setattr(tool_module.reports, "write_list_report", lambda items, **kwargs: state["reported"].extend(items))
    monkeypatch.setattr(sys, "argv", ["find_missing_hash_sidecars"])
    log_error = tool_module.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(tool_module.logger, "log_error", record_error)
    return state


def test_files_without_a_sidecar_entry_are_reported(tool):
    tool["remote"] = {"Game.zip": {"hash": "aaaa"}, "New.zip": {"hash": ""}}

    system.run_main(find_missing_hash_sidecars.main)

    assert tool["reported"] == ["New.zip"]


def test_a_failed_remote_listing_exits_with_an_error(tool):
    tool["remote"] = None

    with pytest.raises(SystemExit) as raised:
        system.run_main(find_missing_hash_sidecars.main)
    assert raised.value.code != 0
    assert tool["errors"] == ["Could not list files on hetzner"]
    assert tool["reported"] == []


def test_a_failed_sidecar_read_exits_with_an_error(tool):
    tool["sidecar"] = None

    with pytest.raises(SystemExit) as raised:
        system.run_main(find_missing_hash_sidecars.main)
    assert raised.value.code != 0
    assert tool["errors"] == ["Could not read the hash sidecar on hetzner"]
    assert tool["reported"] == []


def test_a_remote_without_a_sidecar_reports_every_file(tool):
    tool["sidecar"] = {}

    system.run_main(find_missing_hash_sidecars.main)

    assert tool["reported"] == ["Game.zip"]
