# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import sync_tool


###########################################################
# Exit status
#
# Scripts and timers run sync_tool unattended, so a failed rclone operation
# has to reach them as a non-zero exit rather than only as a log line.
###########################################################

class FakeLockerInfo:

    local_only = False

    def __init__(self, locker_type = None):
        self.root = FakeLockerInfo.root

    def is_local_only(self):
        return FakeLockerInfo.local_only

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


def sync_args(action, *extra):
    return ["-a", action.val(), "-l", "Hetzner", "--no-preview", *extra]


@pytest.fixture
def tool(monkeypatch, tmp_path, isolated_settings):
    FakeLockerInfo.root = str(tmp_path)
    monkeypatch.setattr(FakeLockerInfo, "local_only", False)
    harness = CommandHarness(monkeypatch, sync_tool)
    harness.result = True
    harness.called = []
    harness.kwargs = []
    monkeypatch.setattr(sync_tool.lockerinfo, "LockerInfo", FakeLockerInfo)
    for name in ACTIONS.values():
        def action(name = name, **kwargs):
            harness.called.append(name)
            harness.kwargs.append(kwargs)
            return harness.result
        monkeypatch.setattr(sync_tool.sync, name, action)
    return harness


def test_every_action_has_a_handler():
    assert sorted(ACTIONS, key = str) == sorted(config.RemoteActionType.members(), key = str)


@pytest.mark.parametrize("action", list(ACTIONS))
def test_a_successful_action_exits_cleanly(tool, action):
    tool.run(*sync_args(action))

    assert tool.called == [ACTIONS[action]]


@pytest.mark.parametrize("action", list(ACTIONS))
def test_a_failed_action_exits_with_an_error(tool, action):
    tool.result = False

    assert tool.exit_code(*sync_args(action)) == 1


def test_a_cancelled_preview_runs_nothing_and_is_not_an_error(tool):
    tool.confirm = False

    tool.run("-a", "Diff", "-l", "Hetzner")

    assert tool.called == []


def test_a_locker_with_no_remote_is_refused(tool, monkeypatch):
    # Without a remote type there is nothing for rclone to talk to.
    monkeypatch.setattr(FakeLockerInfo, "local_only", True)

    assert tool.exit_code(*sync_args(config.RemoteActionType.LIST)) != 0
    assert tool.called == []


###########################################################
# Local path, excludes and preview
###########################################################

def test_a_transfer_without_a_local_path_is_refused(tool):
    FakeLockerInfo.root = ""

    assert tool.exit_code(*sync_args(config.RemoteActionType.DOWNLOAD)) != 0
    assert tool.called == []


def test_a_transfer_to_a_missing_local_path_is_refused(tool, tmp_path):
    FakeLockerInfo.root = str(tmp_path / "absent")

    assert tool.exit_code(*sync_args(config.RemoteActionType.UPLOAD)) != 0
    assert tool.called == []


def test_excludes_on_the_command_line_replace_the_configured_ones(tool):
    tool.run(*sync_args(config.RemoteActionType.PUSH, "--excludes", "Cache, Temp,"))

    assert tool.kwargs[0]["excludes"] == ["Cache", "Temp"]


@pytest.mark.parametrize("action", [config.RemoteActionType.DIFF, config.RemoteActionType.DIFFSYNC])
def test_diffs_exclude_the_recycle_folder(tool, action):
    tool.run(*sync_args(action))
    tool.run(*sync_args(action, "--recycle_folder", ""))

    assert [call["excludes"] for call in tool.kwargs] == [[".recycle_bin/**"], []]


def test_the_preview_lists_only_the_paths_that_are_set(tool, monkeypatch, tmp_path):
    tool.run("-a", "List", "-l", "Hetzner")
    FakeLockerInfo.root = ""
    monkeypatch.setattr(FakeLockerInfo, "get_remote_path", lambda self: "")
    tool.run("-a", "List", "-l", "Hetzner")
    previews = [details for _, details in tool.previews]

    assert previews[0] == ["Local: %s" % tmp_path, "Remote: hetzner:/Locker", "Mount: %s" % tmp_path]
    assert previews[1] == []
    assert tool.called == ["list_files", "list_files"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, sync_tool)
