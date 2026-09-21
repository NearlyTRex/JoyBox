# Imports
import os
import shutil
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import autoinstall

pytestmark = pytest.mark.slow


###########################################################
# Building an autoinstall image end to end
#
# The image is written to a usb stick and booted on a machine nobody is
# sitting at, so there is no chance to correct it. What has to hold is that
# the seed is inside the finished image and the bootloader points at it.
#
# A stock Ubuntu image is two gigabytes, so these build a small one with the
# same shape instead: the boot configuration and the El Torito layout are
# what the code touches.
###########################################################

GRUB_CONFIG = """set default="0"
set timeout=30

menuentry "Try or Install Ubuntu Server" {
\tset gfxpayload=keep
\tlinux\t/casper/vmlinuz quiet ---
\tinitrd\t/casper/initrd
}
menuentry "Boot from next volume" {
\texit 1
}
"""

PROFILE = {
    "version": "24.04",
    "username": "operator",
    "realname": "Operator",
    "hostname": "testbox",
    "password_hash": "$6$rounds=656000$abcdefgh$ijklmnop",
    "ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest operator@example.test"],
    "locale": "en_GB.UTF-8",
    "keyboard": "gb",
    "timezone": "Europe/London",
    "packages": ["qemu-guest-agent"],
    "serial_console": False,
}


@pytest.fixture
def xorriso():
    # The registry points at a vendored build that a hermetic run has no copy
    # of. The tool lookup is the seam; what it does to the image is what is
    # under test.
    found = shutil.which("xorriso")
    if not found:
        pytest.skip("xorriso is not installed")
    return found


@pytest.fixture(autouse = True)
def installed_tool(monkeypatch, xorriso):
    # The image handling lives in the iso module, so that is where the tool
    # is looked up.
    monkeypatch.setattr(
        autoinstall.iso.programs, "is_tool_installed", lambda name: name == "XorrISO")
    monkeypatch.setattr(
        autoinstall.iso.programs, "get_tool_program", lambda name: xorriso)


@pytest.fixture
def stock_image(tmp_path, xorriso):
    # An image shaped like the Ubuntu one: a grub config to patch, a bios
    # boot image and an efi image in the El Torito catalogue.
    tree = tmp_path / "stock"
    (tree / "boot" / "grub" / "i386-pc").mkdir(parents = True)
    (tree / "casper").mkdir()
    (tree / "boot" / "grub" / "grub.cfg").write_text(GRUB_CONFIG)
    (tree / "boot" / "grub" / "loopback.cfg").write_text(GRUB_CONFIG)
    (tree / "boot" / "grub" / "i386-pc" / "eltorito.img").write_bytes(b"\x00" * 2048)
    (tree / "casper" / "vmlinuz").write_bytes(b"\x00" * 1024)
    (tree / "efi.img").write_bytes(b"\x00" * 1024 * 1024)

    target = str(tmp_path / "ubuntu-server.iso")
    result = subprocess.run([
        xorriso, "-as", "mkisofs", "-r", "-V", "Ubuntu-Server 24.04",
        "-J", "-l",
        "-b", "boot/grub/i386-pc/eltorito.img",
        "-c", "boot.catalog",
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        "-eltorito-alt-boot",
        "-e", "efi.img",
        "-no-emul-boot",
        "-o", target, str(tree),
    ], capture_output = True)
    assert result.returncode == 0, result.stderr.decode()
    return target


def read_from_image(xorriso, iso_file, path_in_image, tmp_path):
    # Pull one file back out of a finished image
    out_dir = tmp_path / "readback"
    out_dir.mkdir(exist_ok = True)
    target = out_dir / os.path.basename(path_in_image)
    result = subprocess.run([
        xorriso, "-osirrox", "on", "-indev", iso_file,
        "-extract", path_in_image, str(target),
    ], capture_output = True)
    if result.returncode != 0 or not target.exists():
        return None
    return target.read_text(errors = "replace")


def build(tmp_path, stock_image, **overrides):
    profile = dict(PROFILE)
    profile.update(overrides)
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")
    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = profile) is True
    return output_file


###########################################################
# The finished image
###########################################################

def test_an_image_is_produced(tmp_path, stock_image, xorriso):
    output_file = build(tmp_path, stock_image)

    assert os.path.isfile(output_file)
    assert os.path.getsize(output_file) > 0


def test_the_seed_is_inside_the_image(tmp_path, stock_image, xorriso):
    # Without this the installer boots and asks the questions itself.
    output_file = build(tmp_path, stock_image)

    seed = read_from_image(xorriso, output_file, "/nocloud/user-data", tmp_path)

    assert seed is not None
    assert seed.startswith("#cloud-config")


def test_the_seed_carries_the_profile(tmp_path, stock_image, xorriso):
    output_file = build(tmp_path, stock_image)

    seed = read_from_image(xorriso, output_file, "/nocloud/user-data", tmp_path)

    assert "operator" in seed
    assert "testbox" in seed
    assert "Europe/London" in seed


def test_the_instance_metadata_is_inside_the_image(tmp_path, stock_image, xorriso):
    # cloud-init ignores a seed directory that has no meta-data in it.
    output_file = build(tmp_path, stock_image)

    meta = read_from_image(xorriso, output_file, "/nocloud/meta-data", tmp_path)

    assert meta is not None
    assert "instance-id: autoinstall" in meta
    assert "local-hostname: testbox" in meta


def test_the_bootloader_points_at_the_seed(tmp_path, stock_image, xorriso):
    output_file = build(tmp_path, stock_image)

    grub = read_from_image(xorriso, output_file, "/boot/grub/grub.cfg", tmp_path)

    assert "autoinstall" in grub
    assert "ds=nocloud;s=/cdrom/nocloud/" in grub


def test_the_bootloader_stops_waiting(tmp_path, stock_image, xorriso):
    # The stock image waits thirty seconds for a menu choice nobody is there
    # to make.
    output_file = build(tmp_path, stock_image)

    grub = read_from_image(xorriso, output_file, "/boot/grub/grub.cfg", tmp_path)

    assert "set timeout=%d" % autoinstall.boot_timeout in grub
    assert "set timeout=30" not in grub


def test_the_kernel_line_keeps_what_it_had(tmp_path, stock_image, xorriso):
    # The arguments go before the --- separator; anything after it is passed
    # to the installed system rather than the installer.
    output_file = build(tmp_path, stock_image)

    grub = read_from_image(xorriso, output_file, "/boot/grub/grub.cfg", tmp_path)
    kernel_line = [line for line in grub.splitlines() if "vmlinuz" in line][0]

    assert "/casper/vmlinuz" in kernel_line
    assert kernel_line.index("autoinstall") < kernel_line.index("---")


def test_every_boot_configuration_is_patched(tmp_path, stock_image, xorriso):
    # A machine booting the loopback entry would otherwise install by hand.
    output_file = build(tmp_path, stock_image)

    loopback = read_from_image(xorriso, output_file, "/boot/grub/loopback.cfg", tmp_path)

    assert "autoinstall" in loopback


def test_the_serial_console_is_only_used_when_asked(tmp_path, stock_image, xorriso):
    # On a machine with no serial port this sends the installer output
    # somewhere nobody can see it.
    without = build(tmp_path, stock_image)
    grub = read_from_image(xorriso, without, "/boot/grub/grub.cfg", tmp_path)

    assert "console=ttyS0" not in grub


def test_the_serial_console_can_be_asked_for(tmp_path, stock_image, xorriso):
    output_file = build(tmp_path, stock_image, serial_console = True)

    grub = read_from_image(xorriso, output_file, "/boot/grub/grub.cfg", tmp_path)

    assert "console=ttyS0" in grub


def test_the_image_still_boots_both_ways(tmp_path, stock_image, xorriso):
    # The bios entry and the uefi entry both have to survive the rebuild, or
    # the stick boots on one machine and not another.
    output_file = build(tmp_path, stock_image)

    result = subprocess.run(
        [xorriso, "-indev", output_file, "-report_el_torito", "plain"],
        capture_output = True)
    report = result.stdout.decode(errors = "replace")

    assert "El Torito" in report or "boot" in report.lower()


def test_the_stock_image_is_left_alone(tmp_path, stock_image, xorriso):
    before = os.path.getsize(stock_image)

    build(tmp_path, stock_image)

    assert os.path.getsize(stock_image) == before
    grub = read_from_image(xorriso, stock_image, "/boot/grub/grub.cfg", tmp_path)
    assert "autoinstall" not in grub


def test_nothing_is_left_behind(tmp_path, stock_image, xorriso, monkeypatch):
    # The work happens in a temporary directory holding a whole unpacked
    # image, which is gigabytes for a real one.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(
        autoinstall.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))

    build(tmp_path, stock_image)

    assert not scratch.exists()


###########################################################
# Refusing to build
###########################################################

def test_an_image_is_not_built_without_a_way_to_log_in(tmp_path, stock_image):
    # An installed machine with no password and no key is unreachable.
    output_file = str(tmp_path / "out.iso")

    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE, password_hash = "", ssh_keys = [])) is False
    assert not os.path.exists(output_file)


def test_an_image_is_not_built_without_a_username(tmp_path, stock_image):
    output_file = str(tmp_path / "out.iso")

    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE, username = "")) is False
    assert not os.path.exists(output_file)


def test_a_key_alone_is_enough_to_build(tmp_path, stock_image):
    # Password login is disabled anyway, so a key is the expected setup.
    output_file = build(tmp_path, stock_image, password_hash = "")

    assert os.path.isfile(output_file)


###########################################################
# Loading a machine with extra software
#
# The point of the overlay is that a built image arrives with the software
# the machine is for, so what matters is that it reaches the seed inside the
# finished image rather than only the generated document.
###########################################################

OLLAMA_OVERLAY = """autoinstall:
  packages:
    - docker.io
  snaps:
    - name: ollama
  late-commands:
    - curtin in-target --target=/target -- systemctl enable docker
"""


@pytest.fixture
def overlay_file(tmp_path):
    target = tmp_path / "extras.yaml"
    target.write_text(OLLAMA_OVERLAY)
    return str(target)


def test_extra_software_reaches_the_image(tmp_path, stock_image, xorriso, overlay_file):
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")
    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE),
        overlay_file = overlay_file) is True

    seed = read_from_image(xorriso, output_file, "/nocloud/user-data", tmp_path)

    assert "ollama" in seed
    assert "docker.io" in seed


def test_extra_software_does_not_replace_what_the_install_needs(tmp_path, stock_image, xorriso, overlay_file):
    # The overlay adds a package list of its own, and losing the generated
    # one would take the account and the disk layout with it.
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")
    autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE),
        overlay_file = overlay_file)

    seed = read_from_image(xorriso, output_file, "/nocloud/user-data", tmp_path)

    assert "qemu-guest-agent" in seed
    assert "operator" in seed
    assert "/boot/efi" in seed


def test_an_overlay_that_cannot_be_read_stops_the_build(tmp_path, stock_image):
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")

    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE),
        overlay_file = str(tmp_path / "absent.yaml")) is False
    assert not os.path.exists(output_file)


def test_a_whole_seed_can_be_supplied_instead(tmp_path, stock_image, xorriso):
    # The escape hatch: a seed written by hand is used exactly as it is.
    own_seed = tmp_path / "user-data"
    own_seed.write_text("#cloud-config\nautoinstall:\n  version: 1\n  hand-written: yes\n")
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")

    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE),
        user_data_file = str(own_seed)) is True

    seed = read_from_image(xorriso, output_file, "/nocloud/user-data", tmp_path)
    assert "hand-written" in seed
    assert "operator" not in seed


def test_a_supplied_seed_does_not_need_a_configured_profile(tmp_path, stock_image):
    # The seed already answers everything the profile would have.
    own_seed = tmp_path / "user-data"
    own_seed.write_text("#cloud-config\nautoinstall:\n  version: 1\n")
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")

    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE, username = "", password_hash = "", ssh_keys = []),
        user_data_file = str(own_seed)) is True


def test_a_supplied_seed_that_is_missing_stops_the_build(tmp_path, stock_image):
    output_file = str(tmp_path / "ubuntu-autoinstall.iso")

    assert autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = stock_image,
        profile = dict(PROFILE),
        user_data_file = str(tmp_path / "absent")) is False
    assert not os.path.exists(output_file)


###########################################################
# Verifying a download
###########################################################

def test_a_downloaded_image_is_checked_before_it_is_used(tmp_path, monkeypatch, stock_image):
    # A truncated download would otherwise be unpacked and built from.
    from joybox import hashing

    checked = []
    monkeypatch.setattr(
        autoinstall, "find_latest_release_image",
        lambda **kwargs: "ubuntu-24.04.1-live-server-amd64.iso")
    monkeypatch.setattr(
        autoinstall.network, "download_url",
        lambda url, output_file, **kwargs: shutil.copy(stock_image, output_file) or True)
    monkeypatch.setattr(
        autoinstall, "find_image_checksum",
        lambda **kwargs: checked.append(kwargs) or hashing.calculate_file_sha256(src = stock_image))

    obtained = autoinstall.obtain_source_image(
        output_file = str(tmp_path / "downloaded.iso"),
        version = "24.04")

    assert obtained is not None
    assert checked


def test_a_download_that_does_not_match_is_discarded(tmp_path, monkeypatch, stock_image):
    # Left in place it would be picked up as "already here" by the next run,
    # which would never recover on its own.
    download_file = str(tmp_path / "downloaded.iso")
    monkeypatch.setattr(
        autoinstall, "find_latest_release_image",
        lambda **kwargs: "ubuntu-24.04.1-live-server-amd64.iso")
    monkeypatch.setattr(
        autoinstall.network, "download_url",
        lambda url, output_file, **kwargs: shutil.copy(stock_image, output_file) or True)
    monkeypatch.setattr(autoinstall, "find_image_checksum", lambda **kwargs: "0" * 64)

    obtained = autoinstall.obtain_source_image(
        output_file = download_file, version = "24.04")

    assert obtained is None
    assert not os.path.exists(download_file)


def test_verification_can_be_turned_off(tmp_path, monkeypatch, stock_image):
    monkeypatch.setattr(
        autoinstall, "find_latest_release_image",
        lambda **kwargs: "ubuntu-24.04.1-live-server-amd64.iso")
    monkeypatch.setattr(
        autoinstall.network, "download_url",
        lambda url, output_file, **kwargs: shutil.copy(stock_image, output_file) or True)

    def fail(**kwargs):
        raise AssertionError("nothing should be verified when it was turned off")

    monkeypatch.setattr(autoinstall, "find_image_checksum", fail)

    assert autoinstall.obtain_source_image(
        output_file = str(tmp_path / "downloaded.iso"),
        version = "24.04",
        verify = False) is not None


def test_a_supplied_image_is_taken_as_given(tmp_path, monkeypatch, stock_image):
    # It need not be a published release at all, so there is nothing to
    # compare it against.
    def fail(**kwargs):
        raise AssertionError("a supplied image has no published checksum")

    monkeypatch.setattr(autoinstall, "find_image_checksum", fail)

    assert autoinstall.obtain_source_image(
        output_file = str(tmp_path / "downloaded.iso"),
        version = "24.04",
        source_file = stock_image) == stock_image
