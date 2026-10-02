# Imports
import pytest

# Local imports
from joybox import iso
from iso_helpers import BOOT_REPORT


###########################################################
# Finding the efi boot image
#
# It is a hidden el torito entry rather than a file in the tree, so where it
# sits has to be read out of the catalogue. Getting the extent wrong produces
# a plausible looking image of the wrong length, which rebuilds into an iso
# no uefi machine will boot.
###########################################################

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


def efi_only(report):
    return "\n".join(line for line in report.splitlines()
                     if not line.startswith("El Torito img blks"))


def test_an_efi_row_with_unreadable_numbers_is_skipped():
    report = BOOT_REPORT.replace(
        "El Torito boot img :   2  UEFI",
        "El Torito boot img :   3  UEFI  y   none  0x0000  0x00  many  some\n"
        "El Torito boot img :   2  UEFI")

    assert iso.get_efi_boot_image_extent(report) == (1426880, 2574)


@pytest.mark.parametrize("line", [
    "El Torito boot img without a separator UEFI 4 5",
    "El Torito boot img :   UEFI 4",
])
def test_a_malformed_efi_row_is_skipped(line):
    assert iso.get_efi_boot_image_extent(line) is None


def test_a_block_count_for_another_entry_is_ignored():
    report = efi_only(BOOT_REPORT) + "\nEl Torito img blks :   1  4\nEl Torito img blks"

    assert iso.get_efi_boot_image_extent(report) == (1426880, 2574)


def test_an_unreadable_block_count_falls_back_to_the_load_size():
    report = BOOT_REPORT.replace("El Torito img blks :   2  2574", "El Torito img blks :   2  lots")

    assert iso.get_efi_boot_image_extent(report) == (1426880, 2574)


def test_an_efi_entry_with_no_length_yields_nothing():
    report = efi_only(BOOT_REPORT.replace("  10296     1426880", "      0     1426880"))

    assert iso.get_efi_boot_image_extent(report) is None


###########################################################
# Reading the catalogue
###########################################################

def test_the_catalogue_is_read_with_the_tool(installed, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch, output = BOOT_REPORT)

    assert iso.get_iso_boot_report("/Game.iso") == BOOT_REPORT
    assert recorder.only() == [
        "/tools/xorriso", "-indev", "/Game.iso", "-report_el_torito", "plain"]


def test_the_catalogue_without_the_tool_is_nothing(missing, recording_command):
    assert iso.get_iso_boot_report("/Game.iso") is None
    assert recording_command.ran() is False


###########################################################
# Copying a run of bytes out of an image
###########################################################

@pytest.fixture
def image(tmp_path):
    target = tmp_path / "Game.iso"
    target.write_bytes(bytes(range(256)) * 16)
    return target


def test_an_extent_is_copied_exactly(image, tmp_path):
    output = tmp_path / "part.bin"

    assert iso.copy_iso_extent(str(image), str(output), 10, 300) is True
    assert output.read_bytes() == image.read_bytes()[10:310]


def test_an_extent_past_the_end_reports_failure(image, tmp_path):
    # A truncated efi image boots nothing, so a short read is not a copy.
    output = tmp_path / "part.bin"

    assert iso.copy_iso_extent(str(image), str(output), 4000, 500) is False
    assert output.read_bytes() == image.read_bytes()[4000:]


def test_an_extent_of_a_missing_image_reports_failure(tmp_path):
    assert iso.copy_iso_extent(
        str(tmp_path / "absent.iso"), str(tmp_path / "part.bin"), 0, 1) is False


###########################################################
# Extracting the boot data
###########################################################

EFI_BLOCK = 5
EFI_BLOCKS = 2

SMALL_REPORT = (
    "El Torito boot img :   1  UEFI  y   none  0x0000  0x00  8  %d\n"
    "El Torito img blks :   1  %d\n" % (EFI_BLOCK, EFI_BLOCKS))


@pytest.fixture
def bootable_image(tmp_path):
    block = iso.iso_block_size
    data = bytearray(b"M" * block * EFI_BLOCK)
    data += b"E" * block * EFI_BLOCKS
    data += b"T" * block
    target = tmp_path / "Game.iso"
    target.write_bytes(bytes(data))
    return target


@pytest.fixture
def reported(installed, monkeypatch):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, output = SMALL_REPORT)


@pytest.mark.parametrize("verbose", [False, True])
def test_the_boot_data_is_read_out_of_the_image(bootable_image, reported, tmp_path, verbose):
    tree = tmp_path / "tree"
    tree.mkdir()

    assert iso.extract_iso_boot_images(str(bootable_image), str(tree), verbose = verbose) is True
    assert (tree / "efi.img").read_bytes() == b"E" * iso.iso_block_size * EFI_BLOCKS
    mbr = (tree / "mbr.img").read_bytes()
    assert mbr == b"M" * iso.iso_mbr_sectors * iso.el_torito_sector_size


def test_boot_data_already_extracted_is_kept(installed, recording_command, tmp_path):
    (tmp_path / "efi.img").write_bytes(b"e")
    (tmp_path / "mbr.img").write_bytes(b"m")

    assert iso.extract_iso_boot_images("/Game.iso", str(tmp_path)) is True
    assert recording_command.ran() is False


def test_boot_data_is_extracted_again_when_half_is_missing(bootable_image, reported, tmp_path):
    (tmp_path / "efi.img").write_bytes(b"stale")

    assert iso.extract_iso_boot_images(str(bootable_image), str(tmp_path)) is True
    assert (tmp_path / "efi.img").read_bytes() != b"stale"


def test_a_pretend_extraction_writes_nothing(bootable_image, reported, tmp_path):
    assert iso.extract_iso_boot_images(
        str(bootable_image), str(tmp_path), pretend_run = True) is True
    assert not (tmp_path / "efi.img").exists()


def test_an_image_with_no_efi_entry_has_no_boot_data(installed, recording_command,
                                                     bootable_image, tmp_path):
    assert iso.extract_iso_boot_images(str(bootable_image), str(tmp_path)) is False


@pytest.mark.parametrize("failing_call", [0, 1])
def test_a_failed_copy_reports_failure(bootable_image, reported, monkeypatch,
                                       tmp_path, failing_call):
    calls = []

    def copy(*args):
        calls.append(args)
        return len(calls) - 1 != failing_call

    monkeypatch.setattr(iso, "copy_iso_extent", copy)

    assert iso.extract_iso_boot_images(str(bootable_image), str(tmp_path)) is False
    assert len(calls) == failing_call + 1
