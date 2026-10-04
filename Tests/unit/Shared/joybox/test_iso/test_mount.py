# Imports
import pytest

# Local imports
from joybox import iso


###########################################################
# Mount state
###########################################################

def test_a_missing_image_is_not_mounted(tmp_path):
    assert iso.is_iso_mounted(str(tmp_path / "absent.iso"), str(tmp_path)) is False


def test_an_empty_mount_directory_is_not_mounted(tmp_path):
    # An empty directory is the failed-mount signature.
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")
    mount = tmp_path / "mnt"
    mount.mkdir()

    assert iso.is_iso_mounted(str(image), str(mount)) is False


def test_a_populated_mount_directory_is_mounted(tmp_path):
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")
    mount = tmp_path / "mnt"
    mount.mkdir()
    (mount / "file.txt").write_text("content")

    assert iso.is_iso_mounted(str(image), str(mount)) is True


def test_a_missing_mount_directory_is_not_mounted(tmp_path):
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")

    assert iso.is_iso_mounted(str(image), str(tmp_path / "absent")) is False


###########################################################
# Where an image is mounted
#
# Linux mounts into the directory asked for. Windows picks a drive letter of
# its own, and only PowerShell says which.
###########################################################

def test_linux_mounts_where_it_is_asked(linux, recording_command):
    assert iso.get_actual_mount_point("/Game.iso", "/mnt/game") == "/mnt/game"
    assert recording_command.ran() is False


def test_windows_asks_for_the_drive_letter(windows, recording_command):
    iso.get_actual_mount_point("/Game.iso", "/mnt/game")

    assert recording_command.only()[0] == "powershell"
    assert recording_command.value_after("-ImagePath") == "\"/Game.iso\""
    assert recording_command.options().is_shell() is True


@pytest.mark.parametrize("output", [b"E\r\n", "E\n", "E"])
def test_windows_returns_the_drive_root(windows, monkeypatch, output):
    # PowerShell ends its output with a newline, which is not part of the letter.
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = output)

    assert iso.get_actual_mount_point("/Game.iso", "/mnt/game") == "E:\\"


@pytest.mark.parametrize("output", [b"", "", "\r\n", None])
def test_windows_without_a_drive_letter_has_no_mount_point(windows, monkeypatch, output):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = output)

    assert iso.get_actual_mount_point("/Game.iso", "/mnt/game") is None


def test_windows_checks_the_drive_rather_than_the_directory(windows, monkeypatch, tmp_path):
    # The mount directory stays empty on windows; the files are on the drive.
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")
    drive = tmp_path / "drive"
    drive.mkdir()
    (drive / "setup.exe").write_bytes(b"x")
    monkeypatch.setattr(iso, "get_actual_mount_point", lambda iso_file, mount_dir: str(drive))

    assert iso.is_iso_mounted(str(image), str(tmp_path / "mnt")) is True


def test_windows_with_no_drive_is_not_mounted(windows, monkeypatch, tmp_path):
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")
    monkeypatch.setattr(iso, "get_actual_mount_point", lambda iso_file, mount_dir: None)

    assert iso.is_iso_mounted(str(image), str(tmp_path)) is False


###########################################################
# Mounting
###########################################################

@pytest.fixture
def fuse_tools(monkeypatch):
    monkeypatch.setattr(iso, "get_mount_tool", lambda: "/tools/fuseiso")
    monkeypatch.setattr(iso, "get_unmount_tool", lambda: "/tools/fusermount")


def test_a_mounted_image_is_not_mounted_again(linux, fuse_tools, mount_states,
                                              recording_command, tmp_path):
    mount_states(True)

    assert iso.mount_iso("/Game.iso", str(tmp_path / "mnt")) is True
    assert recording_command.ran() is False


def test_linux_mounts_with_fuse(linux, fuse_tools, mount_states, recording_command, tmp_path):
    mount = tmp_path / "mnt"
    mount_states(False, True)

    assert iso.mount_iso("/Game.iso", str(mount)) is True
    assert recording_command.only() == ["/tools/fuseiso", "/Game.iso", str(mount)]
    assert mount.is_dir()


def test_linux_without_fuse_cannot_mount(linux, monkeypatch, mount_states,
                                         recording_command, tmp_path):
    monkeypatch.setattr(iso, "get_mount_tool", lambda: None)
    mount_states(False)

    assert iso.mount_iso("/Game.iso", str(tmp_path / "mnt")) is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_a_failed_mount_is_reported(request, platform, fuse_tools, mount_states,
                                    monkeypatch, tmp_path):
    request.getfixturevalue(platform)
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    mount_states(False)

    assert iso.mount_iso("/Game.iso", str(tmp_path / "mnt")) is False


def test_windows_mounts_with_powershell(windows, mount_states, recording_command, tmp_path):
    mount_states(False, True)

    assert iso.mount_iso("/Game.iso", str(tmp_path / "mnt")) is True
    assert recording_command.only()[:3] == ["powershell", "-Command", "Mount-DiskImage"]
    assert recording_command.value_after("-ImagePath") == "\"/Game.iso\""


def test_a_mount_that_shows_nothing_is_reported(linux, fuse_tools, mount_states,
                                                recording_command, tmp_path):
    mount_states(False, False)

    assert iso.mount_iso("/Game.iso", str(tmp_path / "mnt")) is False


def test_an_unknown_platform_mounts_nothing(other_platform, mount_states,
                                            recording_command, tmp_path):
    mount_states(False, False)

    assert iso.mount_iso("/Game.iso", str(tmp_path / "mnt")) is False
    assert recording_command.ran() is False


###########################################################
# Unmounting
###########################################################

def test_an_image_that_is_not_mounted_needs_no_unmount(linux, fuse_tools, mount_states,
                                                       recording_command, tmp_path):
    mount_states(False)

    assert iso.unmount_iso("/Game.iso", str(tmp_path)) is True
    assert recording_command.ran() is False


def test_linux_unmounts_with_fuse(linux, fuse_tools, mount_states, recording_command, tmp_path):
    mount = tmp_path / "mnt"
    mount.mkdir()
    mount_states(True, False)

    assert iso.unmount_iso("/Game.iso", str(mount)) is True
    assert recording_command.only() == ["/tools/fusermount", "-u", str(mount)]
    assert recording_command.options().get_blocking_processes() == ["/tools/fusermount"]
    assert not mount.exists()


def test_linux_without_fusermount_cannot_unmount(linux, monkeypatch, mount_states,
                                                 recording_command, tmp_path):
    monkeypatch.setattr(iso, "get_unmount_tool", lambda: None)
    mount_states(True)

    assert iso.unmount_iso("/Game.iso", str(tmp_path)) is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_a_failed_unmount_keeps_the_mount_point(request, platform, fuse_tools, mount_states,
                                                monkeypatch, tmp_path):
    request.getfixturevalue(platform)
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    mount = tmp_path / "mnt"
    mount.mkdir()
    mount_states(True)

    assert iso.unmount_iso("/Game.iso", str(mount)) is False
    assert mount.exists()


def test_windows_unmounts_with_powershell(windows, mount_states, recording_command, tmp_path):
    mount_states(True, False)

    assert iso.unmount_iso("/Game.iso", str(tmp_path / "mnt")) is True
    assert recording_command.only()[:3] == ["powershell", "-Command", "Dismount-DiskImage"]


def test_an_unmount_that_leaves_it_mounted_is_reported(linux, fuse_tools, mount_states,
                                                       recording_command, tmp_path):
    mount_states(True, True)

    assert iso.unmount_iso("/Game.iso", str(tmp_path / "mnt")) is False


def test_an_unknown_platform_only_removes_the_mount_point(other_platform, mount_states,
                                                          recording_command, tmp_path):
    mount = tmp_path / "mnt"
    mount.mkdir()
    mount_states(True, False)

    assert iso.unmount_iso("/Game.iso", str(mount)) is True
    assert recording_command.ran() is False
    assert not mount.exists()
