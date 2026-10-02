# Third-party imports
import pytest

# Local imports
from joybox import autoinstall


###########################################################
# Boot configuration
###########################################################

def test_the_installer_is_pointed_at_the_seed():
    arguments = autoinstall.get_kernel_arguments()

    assert "autoinstall" in arguments
    assert "ds=nocloud;s=/cdrom/nocloud/" in arguments


def test_the_serial_console_is_only_added_when_asked():
    assert "console=ttyS0" not in autoinstall.get_kernel_arguments()
    assert "console=ttyS0" in autoinstall.get_kernel_arguments({"serial_console": True})


@pytest.mark.parametrize("line", [
    "\tlinux\t/casper/vmlinuz quiet --- \n",
    "\tlinux\t/casper/vmlinuz quiet ---\n",
    "  append initrd=/casper/initrd quiet ---\n",
])
def test_the_arguments_go_before_the_separator(line):
    # Anything after the separator is passed to the installed system rather
    # than the installer, so it would quietly not autoinstall at all.
    patched = autoinstall.patch_boot_entry(line)

    assert patched.index("autoinstall") < patched.index("---")


def test_a_line_without_a_separator_takes_the_arguments_at_the_end():
    patched = autoinstall.patch_boot_entry("\tlinux\t/casper/vmlinuz quiet\n")

    assert patched.rstrip().endswith("ds=nocloud;s=/cdrom/nocloud/")


def test_a_line_keeps_the_arguments_it_had():
    patched = autoinstall.patch_boot_entry("\tlinux\t/casper/vmlinuz quiet ---\n")

    assert "/casper/vmlinuz" in patched
    assert "quiet" in patched


def test_a_line_already_pointed_at_the_seed_is_left_alone():
    # Building twice from the same tree would otherwise stack the arguments.
    once = autoinstall.patch_boot_entry("\tlinux\t/casper/vmlinuz quiet ---\n")
    twice = autoinstall.patch_boot_entry(once)

    assert once == twice


def test_the_menu_stops_waiting():
    contents = "set default=\"0\"\nset timeout=30\n"

    patched = autoinstall.patch_boot_config_contents(contents)

    assert "set timeout=%d" % autoinstall.boot_timeout in patched
    assert "set timeout=30" not in patched


def test_an_isolinux_menu_stops_waiting():
    # isolinux counts its timeout in tenths of a second.
    patched = autoinstall.patch_boot_config_contents("timeout 300\n")

    assert "timeout %d" % (autoinstall.boot_timeout * 10) in patched


def test_lines_that_are_not_boot_entries_are_untouched():
    contents = "menuentry \"Try or Install Ubuntu Server\" {\n\tset gfxpayload=keep\n}\n"

    assert autoinstall.patch_boot_config_contents(contents) == contents


def test_grub_gets_the_seed_argument_escaped():
    # Grub ends a command at an unescaped semicolon, so the kernel would be
    # loaded with "ds=nocloud" and the seed path read as another command.
    arguments = autoinstall.get_kernel_arguments(escape_semicolons = True)

    assert "ds=nocloud\\;s=/cdrom/nocloud/" in arguments


def test_isolinux_gets_the_seed_argument_as_written():
    # It has no such rule, and an escape would become part of the argument.
    arguments = autoinstall.get_kernel_arguments()

    assert "ds=nocloud;s=/cdrom/nocloud/" in arguments


def test_only_the_grub_configurations_are_escaped():
    found = dict(autoinstall.get_boot_config_files("/iso"))

    assert found["/iso/boot/grub/grub.cfg"] is True
    assert found["/iso/boot/grub/loopback.cfg"] is True
    assert found["/iso/isolinux/txt.cfg"] is False


def test_every_known_boot_configuration_is_looked_for():
    found = [config for config, _ in autoinstall.get_boot_config_files("/iso")]

    assert any(path.endswith("grub.cfg") for path in found)
    assert any(path.endswith("loopback.cfg") for path in found)
    assert any(path.endswith("txt.cfg") for path in found)


def test_the_boot_entries_in_a_configuration_are_patched():
    contents = "menuentry \"Install\" {\n\tlinux\t/casper/vmlinuz quiet ---\n}\n"

    patched = autoinstall.patch_boot_config_contents(contents, escape_semicolons = True)

    assert "\tlinux\t/casper/vmlinuz quiet autoinstall ds=nocloud\\;s=/cdrom/nocloud/ ---\n" in patched
    assert patched.startswith("menuentry \"Install\" {\n")


def test_an_isolinux_append_line_is_patched():
    patched = autoinstall.patch_boot_config_contents("  append initrd=/casper/initrd ---\n")

    assert patched == "  append initrd=/casper/initrd autoinstall ds=nocloud;s=/cdrom/nocloud/ ---\n"


def test_a_line_without_a_newline_does_not_gain_one():
    assert autoinstall.patch_boot_entry("linux /casper/vmlinuz") == \
        "linux /casper/vmlinuz autoinstall ds=nocloud;s=/cdrom/nocloud/"


###########################################################
# Patching an extracted image
###########################################################

GRUB_CONFIG = "set timeout=30\nmenuentry \"Install\" {\n\tlinux\t/casper/vmlinuz quiet ---\n}\n"
ISOLINUX_CONFIG = "timeout 300\nlabel install\n  append initrd=/casper/initrd quiet ---\n"


def extracted_image(tmp_path, grub = GRUB_CONFIG, isolinux = None):
    iso_dir = tmp_path / "iso"
    if grub is not None:
        (iso_dir / "boot" / "grub").mkdir(parents = True)
        (iso_dir / "boot" / "grub" / "grub.cfg").write_text(grub)
    if isolinux is not None:
        (iso_dir / "isolinux").mkdir(parents = True)
        (iso_dir / "isolinux" / "txt.cfg").write_text(isolinux)
    iso_dir.mkdir(exist_ok = True)
    return iso_dir


def test_every_configuration_present_is_patched(tmp_path):
    iso_dir = extracted_image(tmp_path, isolinux = ISOLINUX_CONFIG)

    assert autoinstall.patch_boot_configs(str(iso_dir), {"serial_console": True}) is True

    grub = (iso_dir / "boot" / "grub" / "grub.cfg").read_text()
    isolinux = (iso_dir / "isolinux" / "txt.cfg").read_text()
    assert "ds=nocloud\\;s=/cdrom/nocloud/ console=ttyS0 ---" in grub
    assert "set timeout=2\n" in grub
    assert "ds=nocloud;s=/cdrom/nocloud/ console=ttyS0 ---" in isolinux
    assert "timeout 20\n" in isolinux


def test_an_image_with_no_boot_configuration_is_refused(tmp_path):
    iso_dir = extracted_image(tmp_path, grub = None)

    assert autoinstall.patch_boot_configs(str(iso_dir)) is False


def test_an_empty_configuration_does_not_count(tmp_path):
    iso_dir = extracted_image(tmp_path, grub = "")

    assert autoinstall.patch_boot_configs(str(iso_dir)) is False


def test_a_pretend_run_needs_no_configuration(tmp_path):
    iso_dir = extracted_image(tmp_path, grub = None)

    assert autoinstall.patch_boot_configs(str(iso_dir), pretend_run = True) is True


def test_a_pretend_run_leaves_the_configuration_alone(tmp_path):
    iso_dir = extracted_image(tmp_path)

    assert autoinstall.patch_boot_configs(str(iso_dir), pretend_run = True) is True
    assert (iso_dir / "boot" / "grub" / "grub.cfg").read_text() == GRUB_CONFIG


def test_a_configuration_that_cannot_be_written_fails_the_patch(tmp_path, monkeypatch):
    iso_dir = extracted_image(tmp_path)
    monkeypatch.setattr(autoinstall.serialization, "write_text_file", lambda **kwargs: False)

    assert autoinstall.patch_boot_configs(str(iso_dir)) is False
