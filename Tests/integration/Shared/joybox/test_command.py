# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import command, config


###########################################################
# Installer detection
#
# The detected type decides which silent-install flags get built, so a miss
# means an installer runs interactively or unpacks to the wrong place.
###########################################################

MARKERS = [
    ("Inno Setup", config.InstallerType.INNO),
    ("Nullsoft.NSIS.exehead", config.InstallerType.NSIS),
    ("InstallShieldSetup", config.InstallerType.INS),
    ("7-Zip", config.InstallerType.SEVENZIP),
    ("WinRAR SFX", config.InstallerType.WINRAR),
]

CHUNK = 2048


def write_installer(path, marker, offset = 100, total = 8192):
    payload = bytearray(b"x" * total)
    encoded = marker.encode("utf8")
    payload[offset:offset + len(encoded)] = encoded
    with open(path, "wb") as handle:
        handle.write(bytes(payload))
    return path


@pytest.mark.parametrize("marker,expected", MARKERS, ids = [m for m, _ in MARKERS])
def test_each_installer_marker_is_detected(marker, expected, tmp_path):
    target = write_installer(str(tmp_path / "setup.exe"), marker)
    assert command.get_installer_type(target) == expected


@pytest.mark.parametrize("marker,expected", MARKERS, ids = [m for m, _ in MARKERS])
def test_a_marker_straddling_a_chunk_boundary_is_detected(marker, expected, tmp_path):
    # The file is read in chunks; without a carry-over the marker is split.
    offset = CHUNK - (len(marker) // 2)
    target = write_installer(str(tmp_path / "setup.exe"), marker, offset = offset)

    assert command.get_installer_type(target) == expected


@pytest.mark.parametrize("marker,expected", MARKERS, ids = [m for m, _ in MARKERS])
def test_a_marker_at_every_boundary_offset_is_detected(marker, expected, tmp_path):
    for shift in range(-len(marker), 1):
        target = write_installer(
            str(tmp_path / "setup.exe"), marker, offset = CHUNK + shift)
        assert command.get_installer_type(target) == expected, \
            f"{marker} missed at offset {CHUNK + shift}"


def test_a_marker_in_a_later_chunk_is_detected(tmp_path):
    target = write_installer(
        str(tmp_path / "setup.exe"), "Inno Setup", offset = 6000, total = 8192)

    assert command.get_installer_type(target) == config.InstallerType.INNO


def test_a_file_with_no_marker_is_unknown(tmp_path):
    target = str(tmp_path / "setup.exe")
    with open(target, "wb") as handle:
        handle.write(b"x" * 8192)

    assert command.get_installer_type(target) == config.InstallerType.UNKNOWN


def test_an_empty_file_is_unknown(tmp_path):
    target = str(tmp_path / "setup.exe")
    with open(target, "wb") as handle:
        handle.write(b"")

    assert command.get_installer_type(target) == config.InstallerType.UNKNOWN


def test_undecodable_bytes_do_not_stop_detection(tmp_path):
    # Installers are binaries, so the read is lossy by design.
    target = str(tmp_path / "setup.exe")
    with open(target, "wb") as handle:
        handle.write(bytes(range(256)) * 4 + b"Inno Setup" + b"\xff" * 100)

    assert command.get_installer_type(target) == config.InstallerType.INNO


###########################################################
# Installer setup commands
###########################################################

def test_the_installer_file_leads_the_command():
    built = command.get_installer_setup_command(
        "setup.exe", config.InstallerType.SEVENZIP)

    assert built[0] == "setup.exe"


def test_a_sevenzip_installer_gets_silent_and_output_flags():
    built = command.get_installer_setup_command(
        "setup.exe", config.InstallerType.SEVENZIP, install_dir = "/opt/app")

    assert "-y" in built
    assert "-o/opt/app" in built


def test_a_winrar_installer_gets_its_own_flags():
    built = command.get_installer_setup_command(
        "setup.exe", config.InstallerType.WINRAR, install_dir = "/opt/app")

    assert "-s2" in built
    assert "-d/opt/app" in built


def test_silent_install_can_be_turned_off():
    built = command.get_installer_setup_command(
        "setup.exe", config.InstallerType.SEVENZIP, silent_install = False)

    assert "-y" not in built


def test_no_install_dir_adds_no_output_flag():
    built = command.get_installer_setup_command(
        "setup.exe", config.InstallerType.SEVENZIP)

    assert not any(argument.startswith("-o") for argument in built)


def test_an_unhandled_type_gets_no_flags():
    built = command.get_installer_setup_command(
        "setup.exe", config.InstallerType.INNO, install_dir = "/opt/app")

    assert built == ["setup.exe"]
