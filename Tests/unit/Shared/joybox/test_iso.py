# Imports
import pytest

# Local imports
from joybox import iso


###########################################################
# ISO wrappers
#
# Each builds a xorriso argument list. The flags decide whether long filenames
# and deep paths survive, so they are pinned here; the real round trip lives in
# the integration suite.
###########################################################

@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: "/tools/xorriso")
    return "/tools/xorriso"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(iso.os.path, "exists", lambda path: True)


@pytest.fixture
def no_archive_fallback(monkeypatch):
    # extract_iso tries the archive path first; force it to the tool path.
    monkeypatch.setattr(iso.archive, "extract_archive", lambda **kwargs: False)


@pytest.fixture
def source_image(tmp_path):
    # extract_iso refuses a source that is not there, so it has to exist.
    target = tmp_path / "Game.iso"
    target.write_bytes(b"x")
    return str(target)


@pytest.fixture
def populated_output(monkeypatch):
    monkeypatch.setattr(iso.paths, "does_directory_contain_files", lambda path, **kwargs: True)


###########################################################
# Creating
###########################################################

def test_creating_runs_in_mkisofs_mode(installed, recording_command, existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert "-as" in recording_command.only()
    assert recording_command.value_after("-as") == "mkisofs"


def test_creating_names_the_output(installed, recording_command, existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert recording_command.value_after("-o") == "/out/Game.iso"


def test_creating_passes_the_source_directory(installed, recording_command,
                                              existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert str(tmp_path) in recording_command.only()


def test_creating_uses_iso_level_three(installed, recording_command, existing_output, tmp_path):
    # Level 1 caps filenames at 8.3 and files at 2 GB, which no disc image
    # survives.
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert recording_command.value_after("-iso-level") == "3"


@pytest.mark.parametrize("flag", ["-graft-points", "-full-iso9660-filenames", "-joliet"])
def test_creating_keeps_long_names(installed, recording_command, existing_output, tmp_path, flag):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert flag in recording_command.only()


def test_a_volume_name_is_passed(installed, recording_command, existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path), volume_name = "GAME_DISC")

    assert recording_command.value_after("-volid") == "GAME_DISC"


def test_no_volume_name_leaves_the_flag_out(installed, recording_command,
                                            existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert "-volid" not in recording_command.only()


def test_extra_source_directories_reach_the_command(installed, recording_command,
                                                    existing_output, tmp_path):
    # Declared but unreachable, these produced an empty iso that still reported
    # success.
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    iso.create_iso("/out/Game.iso", source_dirs = [str(first), str(second)])

    assert str(first) in recording_command.only()
    assert str(second) in recording_command.only()


def test_a_source_dir_and_extra_dirs_are_all_passed(installed, recording_command,
                                                    existing_output, tmp_path):
    main = tmp_path / "main"
    extra = tmp_path / "extra"
    main.mkdir()
    extra.mkdir()
    iso.create_iso("/out/Game.iso", source_dir = str(main), source_dirs = [str(extra)])

    assert str(main) in recording_command.only()
    assert str(extra) in recording_command.only()


def test_creating_without_the_tool_reports_failure(missing, recording_command, tmp_path):
    assert iso.create_iso("/out/Game.iso", source_dir = str(tmp_path)) is False
    assert recording_command.ran() is False


def test_creating_declares_its_output_path(installed, recording_command,
                                           existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert "/out/Game.iso" in recording_command.options().get_output_paths()


def test_a_failed_create_does_not_delete_the_source(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must not be removed after a failure")

    monkeypatch.setattr(iso.fileops, "remove_directory", fail)

    assert iso.create_iso("/out/Game.iso", source_dir = str(tmp_path),
                          delete_original = True) is False


###########################################################
# Extracting
###########################################################

def test_the_archive_path_is_tried_first(installed, monkeypatch, recording_command,
                                         source_image):
    # 7z reads an iso directly and is faster; xorriso is the fallback.
    monkeypatch.setattr(iso.archive, "extract_archive", lambda **kwargs: True)

    assert iso.extract_iso(source_image, "/out") is True
    assert recording_command.ran() is False


def test_extracting_falls_back_to_the_tool(installed, recording_command,
                                           populated_output, no_archive_fallback,
                                           source_image):
    iso.extract_iso(source_image, "/out")

    assert recording_command.ran() is True
    assert recording_command.value_after("-indev") == source_image


def test_extracting_enables_the_extraction_mode(installed, recording_command,
                                                populated_output, no_archive_fallback,
                                                source_image):
    iso.extract_iso(source_image, "/out")

    assert recording_command.value_after("-osirrox") == "on"


def test_extracting_takes_the_whole_image(installed, recording_command,
                                          populated_output, no_archive_fallback,
                                          source_image):
    iso.extract_iso(source_image, "/out")

    assert recording_command.value_after("-extract") == "/"


def test_extracting_names_the_target_directory(installed, recording_command,
                                               populated_output, no_archive_fallback,
                                               source_image):
    iso.extract_iso(source_image, "/out")
    cmd = recording_command.only()

    assert cmd[cmd.index("-extract") + 2] == "/out"


def test_extracting_without_the_tool_reports_failure(missing, recording_command,
                                                     no_archive_fallback, source_image):
    assert iso.extract_iso(source_image, "/out") is False


def test_extracting_a_missing_image_reports_failure(installed, recording_command,
                                                    no_archive_fallback, tmp_path):
    # xorriso writes an empty directory and exits 0 for a source that is not an
    # iso, so the source is checked before it runs.
    assert iso.extract_iso(str(tmp_path / "absent.iso"), "/out") is False
    assert recording_command.ran() is False


def test_an_empty_extraction_reports_failure(installed, recording_command,
                                             no_archive_fallback, source_image,
                                             monkeypatch):
    monkeypatch.setattr(iso.paths, "does_directory_contain_files", lambda path, **kwargs: False)

    assert iso.extract_iso(source_image, "/out") is False


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
# Packing an image that boots
#
# An installer image has to boot on an old machine through its bios entry and
# on a new one through its uefi entry, from the same file written to a usb
# stick. Dropping either entry makes a stick that works on one and not the
# other, which is only found at the machine it was carried to.
###########################################################

def bootable_command(**kwargs):
    defaults = dict(
        iso_tool = "/tools/xorriso",
        iso_file = "/out.iso",
        source_dir = "/tree",
        volume_name = "A Volume",
        bios_boot_image = "boot/grub/i386-pc/eltorito.img",
        efi_boot_image = "/work/efi.img",
        mbr_image = "/work/mbr.img")
    defaults.update(kwargs)
    return iso.get_bootable_iso_command(**defaults)


def test_a_bootable_image_is_packed_from_its_tree():
    command = bootable_command()

    assert command[0] == "/tools/xorriso"
    assert command[-1] == "/tree"
    assert "/out.iso" in command


def test_a_bootable_image_keeps_its_bios_entry():
    command = bootable_command()

    assert "boot/grub/i386-pc/eltorito.img" in command
    assert "-boot-info-table" in command


def test_a_bootable_image_keeps_its_uefi_entry():
    command = bootable_command()

    assert "-eltorito-alt-boot" in command
    assert "/work/efi.img" in command


def test_a_bootable_image_can_be_written_to_a_usb_stick():
    # An el torito catalogue alone is an optical image. Firmware booting a
    # stick looks for a partition table, so the efi image is appended as a
    # partition of its own and the boot code goes back in the system area.
    command = bootable_command()

    assert "-append_partition" in command
    assert iso.efi_partition_type in command
    assert "-appended_part_as_gpt" in command
    assert "--protective-msdos-label" in command
    assert "--grub2-mbr" in command
    assert "/work/mbr.img" in command


def test_the_appended_partition_is_declared_before_it_is_referenced():
    # xorriso reads the options in order, so a catalogue entry pointing at a
    # partition that has not been appended yet is not resolved.
    command = bootable_command()

    assert command.index("-append_partition") < command.index("-eltorito-alt-boot")


def test_the_uefi_entry_points_at_the_appended_partition():
    # Pointing it at a file in the tree instead would pack the same five
    # megabytes twice and leave the partition unreferenced.
    command = bootable_command()

    assert any(
        entry.startswith("--interval:appended_partition_2") for entry in command)


def test_an_image_with_no_boot_code_asks_for_none():
    command = bootable_command(mbr_image = None)

    assert "--grub2-mbr" not in command
    assert "--protective-msdos-label" not in command


def test_an_image_with_no_bios_entry_asks_for_none():
    command = bootable_command(bios_boot_image = None)

    assert "-boot-info-table" not in command
    assert "-eltorito-alt-boot" in command


def test_an_image_with_no_uefi_entry_asks_for_none():
    command = bootable_command(efi_boot_image = None)

    assert "-eltorito-alt-boot" not in command
    assert "-append_partition" not in command


def test_a_bootable_image_is_named():
    assert "A Volume" in bootable_command()


def test_a_bootable_image_needs_no_name():
    command = bootable_command(volume_name = None)

    assert "-V" not in command


def test_the_extracted_boot_data_is_named_apart():
    # Both are kept beside the tree rather than in it, since they are
    # appended to the rebuilt image rather than packed as files.
    assert iso.get_iso_efi_boot_image("/work").endswith("efi.img")
    assert iso.get_iso_mbr_image("/work").endswith("mbr.img")
    assert iso.get_iso_efi_boot_image("/work") != iso.get_iso_mbr_image("/work")


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


###########################################################
# Finding the efi boot image
#
# It is a hidden el torito entry rather than a file in the tree, so where it
# sits has to be read out of the catalogue. Getting the extent wrong produces
# a plausible looking image of the wrong length, which rebuilds into an iso
# no uefi machine will boot.
###########################################################

# As xorriso prints it, including the colon in its own label
BOOT_REPORT = """Drive current: -indev '/images/ubuntu.iso'
Volume id    : 'Ubuntu-Server 26.04.1 LTS amd64'
El Torito catalog  : 798  1
El Torito cat path : /boot.catalog
El Torito images   :   N  Pltf  B   Emul  Ld_seg  Hdpt  Ldsiz         LBA
El Torito boot img :   1  BIOS  y   none  0x0000  0x00      4         799
El Torito boot img :   2  UEFI  y   none  0x0000  0x00  10296     1426880
El Torito img path :   1  /boot/grub/i386-pc/eltorito.img
El Torito img opts :   1  boot-info-table grub2-boot-info
El Torito img blks :   2  2574
"""


def test_the_efi_entry_is_found_in_a_real_report():
    assert iso.get_efi_boot_image_extent(BOOT_REPORT) == (1426880, 2574)


def test_the_bios_entry_is_not_mistaken_for_the_efi_one():
    # The bios image is listed first and is a few kilobytes; rebuilding with
    # it in place of the efi image produces an iso that boots on nothing.
    block, blocks = iso.get_efi_boot_image_extent(BOOT_REPORT)

    assert (block, blocks) != (799, 4)


def test_the_block_count_is_taken_from_the_catalogue_not_the_row_number():
    # The label carries its own colon, so counting columns from the start of
    # the line reads the entry number as the length and copies two blocks.
    _, blocks = iso.get_efi_boot_image_extent(BOOT_REPORT)

    assert blocks * iso.iso_block_size == 5271552


def test_a_load_size_is_used_when_no_block_count_is_given():
    # 10296 sectors of 512 bytes is 2574 blocks of 2048.
    report = "\n".join(
        line for line in BOOT_REPORT.splitlines()
        if not line.startswith("El Torito img blks"))

    assert iso.get_efi_boot_image_extent(report) == (1426880, 2574)


def test_a_load_size_that_does_not_divide_evenly_is_rounded_up():
    # A short final block still has to be copied, or the image is truncated.
    report = BOOT_REPORT.replace("  10296     1426880", "      5     1426880")
    report = "\n".join(
        line for line in report.splitlines()
        if not line.startswith("El Torito img blks"))

    assert iso.get_efi_boot_image_extent(report) == (1426880, 2)


@pytest.mark.parametrize("report", [None, "", "not a report", b""])
def test_a_report_without_an_efi_entry_yields_nothing(report):
    assert iso.get_efi_boot_image_extent(report) is None


def test_an_image_with_only_a_bios_entry_yields_nothing():
    report = "\n".join(
        line for line in BOOT_REPORT.splitlines()
        if "UEFI" not in line)

    assert iso.get_efi_boot_image_extent(report) is None


def test_a_report_read_as_bytes_is_understood():
    assert iso.get_efi_boot_image_extent(BOOT_REPORT.encode()) == (1426880, 2574)
