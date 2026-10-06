# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import rebuild_hash_sidecars


###########################################################
# Rebuild flow
#
# The sidecar is what master_backup and locker_sync_tool compare against, so a
# failed clear or upload has to stop the run with a non-zero exit.
###########################################################

class FakeLockerInfo:

    root = None
    remote_path = "/Locker"
    excludes = ()

    def __init__(self, locker_type = None):
        self.locker_type = locker_type

    def get_mount_path(self):
        return FakeLockerInfo.root

    def get_name(self):
        return "hetzner"

    def get_type(self):
        return config.RemoteType.SFTP.val()

    def get_remote_path(self):
        return FakeLockerInfo.remote_path

    def get_excluded_dirs(self):
        return FakeLockerInfo.excludes


@pytest.fixture
def tool(monkeypatch, tmp_path, isolated_settings):
    tool_module = rebuild_hash_sidecars
    FakeLockerInfo.root = str(tmp_path)
    FakeLockerInfo.remote_path = "/Locker"
    FakeLockerInfo.excludes = ()
    harness = CommandHarness(monkeypatch, tool_module)
    harness.configured = True
    harness.clear = True
    harness.upload = True
    harness.cleared = []
    harness.uploaded = []
    monkeypatch.setattr(tool_module.lockerinfo, "LockerInfo", FakeLockerInfo)
    monkeypatch.setattr(tool_module.sync, "is_remote_configured", lambda name, remote_type: harness.configured)

    def clear(**kwargs):
        harness.cleared.append(kwargs)
        return harness.clear

    def upload(**kwargs):
        harness.uploaded.append(kwargs)
        return harness.upload

    monkeypatch.setattr(tool_module.sync, "clear_hash_sidecar_files", clear)
    monkeypatch.setattr(tool_module.sync, "upload_hash_sidecar_files", upload)
    return harness


def test_whole_locker_is_hashed_into_the_destination_root(tool, tmp_path):
    tool.run("--no-preview")

    assert tool.cleared == []
    upload = tool.uploaded[0]
    assert upload["remote_name"] == "hetzner"
    assert upload["remote_path"] == "/Locker"
    assert upload["local_path"] == str(tmp_path)
    assert upload["local_root"] == "/Locker"
    assert upload["skip_existing"] is False
    assert tool.errors == []


def test_subpath_narrows_both_sides_but_keeps_the_root_database(tool, tmp_path):
    (tmp_path / "Gaming" / "Roms").mkdir(parents = True)

    tool.run("--no-preview", "--path", "Gaming/Roms", "-s", "-r", "2", "-f", "3")

    upload = tool.uploaded[0]
    assert upload["local_path"] == str(tmp_path / "Gaming" / "Roms")
    assert upload["remote_path"] == "/Locker/Gaming/Roms"
    assert upload["local_root"] == "/Locker"
    assert upload["skip_existing"] is True
    assert (upload["parallel_dirs"], upload["parallel_files"]) == (2, 3)


def test_a_remote_without_a_path_uses_its_top_level(tool):
    FakeLockerInfo.remote_path = None

    tool.run("--no-preview")

    assert tool.uploaded[0]["local_root"] == ""


def test_clear_always_targets_the_destination_root(tool, tmp_path):
    (tmp_path / "Music").mkdir()

    tool.run("--no-preview", "-c", "--path", "Music")

    assert tool.cleared[0]["remote_path"] == "/Locker"
    assert tool.uploaded[0]["remote_path"] == "/Locker/Music"


def test_failed_clear_stops_before_uploading(tool):
    tool.clear = False

    assert tool.exit_code("--no-preview", "-c") == 1
    assert tool.errors == ["Failed to clear sidecars"]
    assert tool.uploaded == []


def test_failed_upload_exits_with_an_error(tool):
    tool.upload = False

    assert tool.exit_code("--no-preview") == 1
    assert tool.errors == ["Rebuild failed"]


def test_missing_source_path_quits(tool, tmp_path):
    assert tool.exit_code("--no-preview", "--path", "Nowhere") != 0
    assert tool.errors == ["Source path not accessible: %s" % (tmp_path / "Nowhere")]
    assert tool.uploaded == []


def test_unconfigured_remote_quits(tool):
    tool.configured = False

    assert tool.exit_code("--no-preview") != 0
    assert tool.errors == ["Remote 'hetzner' is not configured"]
    assert tool.uploaded == []


def test_preview_lists_the_plan_and_memory_ceiling(tool, tmp_path):
    FakeLockerInfo.excludes = ("Testing", "Cache")

    tool.run("-c", "-s", "-r", "2", "-f", "2")

    chunk_mb = config.hash_chunk_size // (1024 * 1024)
    assert [details for _, details in tool.previews] == [[
        "Source: %s" % tmp_path,
        "Destination: hetzner:/Locker/.locker_hashes.db",
        "Parallel dirs: 2, Parallel files: 2",
        "Max memory usage: %d MB (2 × 2 × %d MB chunk)" % (4 * chunk_mb, chunk_mb),
        "Excluded dirs: Testing, Cache",
        "Clear existing sidecars: Yes",
        "Skip existing sidecars: Yes",
    ]]
    assert len(tool.uploaded) == 1


def test_declined_preview_changes_nothing(tool):
    tool.confirm = False

    tool.run("-c")

    assert len(tool.previews[0][1]) == 5
    assert tool.cleared == []
    assert tool.uploaded == []


def test_preview_without_excludes_or_flags(tool, tmp_path):
    tool.run()

    assert len(tool.previews[0][1]) == 4
    assert len(tool.uploaded) == 1


def test_run_goes_through_the_shared_error_handling(tool):
    tool.upload = False

    tool.exit_code("--no-preview")
    assert tool.errors == ["Rebuild failed"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, rebuild_hash_sidecars)
