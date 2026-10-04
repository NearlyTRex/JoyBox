# Local imports
from joybox import iso
from iso_helpers import bootable_command


###########################################################
# Packing an image that boots
#
# An installer image has to boot on an old machine through its bios entry and
# on a new one through its uefi entry, from the same file written to a usb
# stick. Dropping either entry makes a stick that works on one and not the
# other, which is only found at the machine it was carried to.
###########################################################

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
# Running the packer
###########################################################

def test_packing_runs_the_bootable_command(installed, recording_command, tmp_path):
    image = tmp_path / "out.iso"
    image.write_bytes(b"x")

    assert iso.create_bootable_iso(
        str(image), "/tree", volume_name = "A Volume",
        efi_boot_image = "/work/efi.img") is True
    assert recording_command.only() == iso.get_bootable_iso_command(
        iso_tool = "/tools/xorriso", iso_file = str(image), source_dir = "/tree",
        volume_name = "A Volume", efi_boot_image = "/work/efi.img")
    assert str(image) in recording_command.options().get_output_paths()


def test_packing_without_the_tool_reports_failure(missing, recording_command):
    assert iso.create_bootable_iso("/out.iso", "/tree") is False
    assert recording_command.ran() is False


def test_a_failed_pack_reports_failure(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    image = tmp_path / "out.iso"
    image.write_bytes(b"x")

    assert iso.create_bootable_iso(str(image), "/tree") is False


def test_a_pack_that_writes_nothing_reports_failure(installed, recording_command, tmp_path):
    assert iso.create_bootable_iso(str(tmp_path / "out.iso"), "/tree") is False


def test_a_pretend_pack_succeeds_without_an_image(installed, recording_command, tmp_path):
    assert iso.create_bootable_iso(
        str(tmp_path / "out.iso"), "/tree", pretend_run = True) is True
