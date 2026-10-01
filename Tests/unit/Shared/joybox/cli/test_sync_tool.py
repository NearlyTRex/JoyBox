# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, system
from joybox.cli import sync_tool


###########################################################
# Exit status
#
# Scripts and timers run sync_tool unattended, so a failed rclone operation
# has to reach them as a non-zero exit rather than only as a log line.
###########################################################

class FakeLockerInfo:

    def __init__(self, locker_type = None):
        self.root = FakeLockerInfo.root

    def get_type(self):
        return config.RemoteType.SFTP.val()

    def get_name(self):
        return "hetzner"

    def get_remote_path(self):
        return "/Locker"

    def get_token(self):
        return None

    def get_config(self):
        return "{}"

    def get_mount_path(self):
        return self.root

    def get_mount_flags(self):
        return []

    def get_excluded_dirs(self):
        return []


ACTIONS = {
    config.RemoteActionType.INIT: "setup_remote",
    config.RemoteActionType.DOWNLOAD: "download_files_from_remote",
    config.RemoteActionType.UPLOAD: "upload_files_to_remote",
    config.RemoteActionType.PULL: "pull_files_from_remote",
    config.RemoteActionType.PUSH: "push_files_to_remote",
    config.RemoteActionType.MERGE: "merge_files_both_ways",
    config.RemoteActionType.DIFF: "diff_files",
    config.RemoteActionType.DIFFSYNC: "diff_sync_files",
    config.RemoteActionType.EMPTYRECYCLE: "empty_recycle_bin",
    config.RemoteActionType.LIST: "list_files",
    config.RemoteActionType.MOUNT: "mount_files",
}


@pytest.fixture
def tool(monkeypatch, tmp_path, isolated_settings):
    FakeLockerInfo.root = str(tmp_path)
    state = {"result": True, "called": []}
    monkeypatch.setattr(sync_tool.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(sync_tool.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(sync_tool.lockerinfo, "LockerInfo", FakeLockerInfo)
    for name in ACTIONS.values():
        def action(name = name, **kwargs):
            state["called"].append(name)
            return state["result"]
        monkeypatch.setattr(sync_tool.sync, name, action)

    def run(action, *extra):
        monkeypatch.setattr(sys, "argv", ["sync_tool", "-a", action.val(), "-l", "Hetzner", "--no-preview", *extra])
        return system.run_main(sync_tool.main)

    state["run"] = run
    return state


@pytest.mark.parametrize("action", list(ACTIONS))
def test_a_successful_action_exits_cleanly(tool, action):
    tool["run"](action)

    assert tool["called"] == [ACTIONS[action]]


@pytest.mark.parametrize("action", list(ACTIONS))
def test_a_failed_action_exits_with_an_error(tool, action):
    tool["result"] = False

    with pytest.raises(SystemExit) as raised:
        tool["run"](action)
    assert raised.value.code == 1


def test_a_cancelled_preview_runs_nothing_and_is_not_an_error(tool, monkeypatch):
    monkeypatch.setattr(sync_tool.prompts, "prompt_for_preview", lambda title, details: False)
    monkeypatch.setattr(sys, "argv", ["sync_tool", "-a", "Diff", "-l", "Hetzner"])

    system.run_main(sync_tool.main)

    assert tool["called"] == []
