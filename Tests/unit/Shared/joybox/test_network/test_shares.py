# Imports
import ctypes
import os
import stat
import types
import pytest

# Local imports
from joybox import network


###########################################################
# Network shares
###########################################################

def test_a_mounted_share_is_recognised(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "//server/share on /mnt/share type cifs (rw)")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is True


def test_a_share_mounted_somewhere_else_is_not_recognised(monkeypatch):
    # Two mounts of the same share is how a backup ends up written to the
    # wrong directory.
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "//server/share on /mnt/other type cifs (rw)")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


def test_an_unmounted_share_is_not_recognised(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(network.command, "run_output_command", lambda cmd: "")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


def test_a_windows_share_is_recognised_by_its_contents(monkeypatch, tmp_path):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: True)
    (tmp_path / "file.txt").write_text("data")

    assert network.is_network_share_mounted(str(tmp_path), "server", "share") is True


def test_an_empty_windows_mount_point_is_not_a_share(monkeypatch, tmp_path):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: True)

    assert network.is_network_share_mounted(str(tmp_path), "server", "share") is False


def test_a_share_on_a_neighbouring_mount_point_is_not_recognised(monkeypatch):
    # /mnt/share2 contains /mnt/share as text but is a different directory.
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "//server/share on /mnt/share2 type cifs (rw)")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


def test_a_neighbouring_share_is_not_recognised(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "//server/shared on /mnt/share type cifs (rw)")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


def test_a_mount_point_with_a_trailing_slash_is_recognised(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "/dev/sda1 on / type ext4 (rw)\n//server/share on /mnt/share type cifs (rw)\n")

    assert network.is_network_share_mounted("/mnt/share/", "server", "share") is True


def test_an_unknown_platform_has_no_shares_mounted(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: False)

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


###########################################################
# Mounting
###########################################################

SHARE_SECRET = "hun,ter2"


@pytest.fixture
def linux(monkeypatch, tmp_path):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    monkeypatch.setattr(network.tempfile, "tempdir", str(credentials_dir))
    return credentials_dir


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: True)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: False)


@pytest.fixture
def mount_run(monkeypatch):
    # Records each command and, for the mount itself, the credentials file it named
    state = {"calls": [], "codes": {"mkdir": 0, "mount": 0}, "listing": "", "credentials": None}

    def run_returncode_command(cmd, **kwargs):
        state["calls"].append(list(cmd))
        if cmd[1] == "mount":
            option = cmd[cmd.index("-o") + 1]
            path = option.split(",")[0].removeprefix("credentials=")
            state["credentials_path"] = path
            if os.path.exists(path):
                state["credentials"] = (open(path).read(), stat.S_IMODE(os.stat(path).st_mode))
        return state["codes"][cmd[1]]

    def run_output_command(cmd, **kwargs):
        state["calls"].append(list(cmd))
        return state["listing"]

    monkeypatch.setattr(network.command, "run_returncode_command", run_returncode_command)
    monkeypatch.setattr(network.command, "run_output_command", run_output_command)
    return state


def mount(mount_dir, **kwargs):
    return network.mount_network_share(mount_dir, "server", "share", "aryie", SHARE_SECRET, **kwargs)


def test_a_linux_share_is_mounted_over_cifs(linux, mount_run):
    assert mount("/mnt/share") is True

    mkdir, listing, mount_cmd = mount_run["calls"]
    assert mkdir == ["sudo", "mkdir", "-p", "/mnt/share"]
    assert listing == ["mount"]
    assert mount_cmd[:5] == ["sudo", "mount", "-t", "cifs", "-o"]
    assert mount_cmd[5].startswith("credentials=%s," % mount_run["credentials_path"])
    assert mount_cmd[-2:] == ["//server/share", "/mnt/share"]


def test_the_password_never_reaches_the_command_line(linux, mount_run):
    # Arguments are visible to every user through ps.
    mount("/mnt/share")

    assert not any(SHARE_SECRET in part for cmd in mount_run["calls"] for part in cmd)


def test_the_credentials_file_holds_the_login_verbatim(linux, mount_run):
    # A comma in the password would split a -o option string.
    mount("/mnt/share")

    content, mode = mount_run["credentials"]
    assert content == "username=aryie\npassword=%s\n" % SHARE_SECRET
    assert mode == 0o600


def test_credentials_stay_in_the_temp_dir(linux):
    assert network.get_cifs_credentials_dir() == str(linux)


def test_a_temp_dir_with_a_comma_is_not_used_for_credentials(linux, monkeypatch, mount_run):
    # The credentials path is itself part of the comma-separated -o string.
    comma_dir = linux / "a,b"
    comma_dir.mkdir()
    monkeypatch.setattr(network.tempfile, "tempdir", str(comma_dir))

    assert network.get_cifs_credentials_dir() == "/tmp"
    mount("/mnt/share", pretend_run = True)
    assert mount_run["credentials_path"] == "/tmp/joybox-cifs-pretend.cred"


@pytest.mark.parametrize("code, expected", [(0, True), (32, False)])
def test_the_credentials_file_is_removed_after_the_mount(linux, mount_run, code, expected):
    mount_run["codes"]["mount"] = code

    assert mount("/mnt/share") is expected
    assert mount_run["credentials"] is not None
    assert list(linux.iterdir()) == []


def test_the_credentials_file_is_removed_when_the_mount_raises(linux, monkeypatch):
    def run_returncode_command(cmd, **kwargs):
        if cmd[1] == "mount":
            raise SystemExit(1)
        return 0

    monkeypatch.setattr(network.command, "run_returncode_command", run_returncode_command)
    monkeypatch.setattr(network.command, "run_output_command", lambda cmd, **kwargs: "")

    with pytest.raises(SystemExit):
        mount("/mnt/share", exit_on_failure = True)
    assert list(linux.iterdir()) == []


def test_a_pretend_linux_mount_writes_no_credentials(linux, mount_run):
    assert mount("/mnt/share", pretend_run = True) is True

    assert mount_run["calls"][-1][:2] == ["sudo", "mount"]
    assert mount_run["credentials"] is None
    assert list(linux.iterdir()) == []


def test_an_already_mounted_linux_share_is_not_mounted_again(linux, mount_run):
    mount_run["listing"] = "//server/share on /mnt/share type cifs (rw)"

    assert mount("/mnt/share") is True
    assert [cmd[:2] for cmd in mount_run["calls"]] == [["sudo", "mkdir"], ["mount"]]


def test_a_populated_local_directory_is_not_taken_for_the_share(linux, mount_run, tmp_path):
    # Backups written there would land on local disk instead of the share.
    (tmp_path / "local.txt").write_text("not the share")

    assert mount(str(tmp_path)) is True
    assert mount_run["calls"][-1][:2] == ["sudo", "mount"]


def test_a_linux_mount_point_that_cannot_be_made_fails(linux, mount_run):
    mount_run["codes"]["mkdir"] = 1

    assert mount("/mnt/share") is False
    assert len(mount_run["calls"]) == 1


@pytest.mark.parametrize("username, password", [("aryie\ndomain=evil", SHARE_SECRET), ("aryie", "pass\ndomain=evil")])
def test_credentials_with_a_line_break_are_refused(linux, mount_run, username, password):
    # A line break would add lines of its own to the credentials file.
    assert network.mount_network_share("/mnt/share", "server", "share", username, password) is False
    assert mount_run["calls"] == []


def test_credentials_with_a_line_break_can_quit_the_program(linux, mount_run):
    with pytest.raises(SystemExit):
        network.mount_network_share(
            "/mnt/share", "server", "share", "aryie", "pass\nword", exit_on_failure = True)


@pytest.fixture
def mapped(monkeypatch):
    state = {"calls": [], "code": 0}

    def map_windows_drive(drive, remote, username, password):
        state["calls"].append((drive, remote, username, password))
        return state["code"]

    monkeypatch.setattr(network, "map_windows_drive", map_windows_drive)
    monkeypatch.setattr(network.paths, "is_path_directory", lambda path: False)
    monkeypatch.setattr(network.paths, "get_directory_drive", lambda path: "z")
    return state


def test_a_windows_share_is_mapped_to_its_drive(windows, mapped, recording_command):
    assert mount("Z:\\", verbose = True) is True

    assert mapped["calls"] == [("z:", "\\\\server\\share", "aryie", SHARE_SECRET)]
    assert recording_command.ran() is False


def test_a_mapped_windows_drive_is_not_mapped_again(windows, monkeypatch, tmp_path):
    monkeypatch.setattr(network, "map_windows_drive", lambda *args: pytest.fail("mapped again"))

    assert mount(str(tmp_path)) is True


def test_a_failed_windows_mapping_fails(windows, mapped):
    mapped["code"] = 86

    assert mount("Z:\\") is False


def test_a_failed_windows_mapping_can_quit_the_program(windows, mapped):
    mapped["code"] = 86

    with pytest.raises(SystemExit):
        mount("Z:\\", exit_on_failure = True)


def test_a_pretend_windows_mapping_maps_nothing(windows, mapped):
    assert mount("Z:\\", pretend_run = True) is True
    assert mapped["calls"] == []


def test_a_windows_mapping_hands_the_password_to_the_api(monkeypatch):
    seen = []

    def add_connection(resource, password, username, flags):
        seen.append((resource._obj.lpLocalName, resource._obj.lpRemoteName, resource._obj.dwType, password, username, flags))
        return 0

    fake = types.SimpleNamespace(mpr = types.SimpleNamespace(WNetAddConnection2W = add_connection))
    monkeypatch.setattr(ctypes, "windll", fake, raising = False)

    assert network.map_windows_drive("z:", "\\\\server\\share", "aryie", SHARE_SECRET) == 0
    assert seen == [("z:", "\\\\server\\share", 1, SHARE_SECRET, "aryie", 0)]


def test_an_unknown_platform_mounts_nothing(monkeypatch, recording_command):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: False)

    assert mount("/mnt/share") is False
    assert recording_command.ran() is False
