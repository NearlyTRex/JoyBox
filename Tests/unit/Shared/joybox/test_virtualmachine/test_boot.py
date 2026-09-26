# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import virtualmachine
from vm_helpers import record


###########################################################
# Booting an image directly
#
# This is how an installer image is tried before a usb stick and a real
# machine. What has to hold is that the machine boots the way the target will
# - uefi firmware, the image in the drive, a blank disk to install onto - and
# that it stops when the install is done rather than starting over.
###########################################################

BOOT_NAME = "llm"


def boot_command(**kwargs):
    defaults = dict(
        disk_image = "/vms/llm.qcow2",
        firmware_code = "/fw/code.fd",
        firmware_vars = "/vms/llm-vars.fd")
    defaults.update(kwargs)
    return virtualmachine.get_boot_command(**defaults)


###########################################################
# Firmware
###########################################################

def test_a_firmware_pair_is_found_where_a_distribution_puts_it(monkeypatch):
    pairs = [("/absent/code.fd", "/absent/vars.fd"), ("/here/code.fd", "/here/vars.fd")]
    monkeypatch.setattr(
        virtualmachine.paths, "is_path_file", lambda path: path.startswith("/here/"))

    assert virtualmachine.get_firmware_pair(pairs) == ("/here/code.fd", "/here/vars.fd")


def test_half_a_firmware_pair_is_not_enough(monkeypatch):
    # The variables file is written to while the machine runs, so a code file
    # on its own cannot be used.
    pairs = [("/here/code.fd", "/here/vars.fd")]
    monkeypatch.setattr(
        virtualmachine.paths, "is_path_file", lambda path: path.endswith("code.fd"))

    assert virtualmachine.get_firmware_pair(pairs) is None


def test_no_firmware_at_all_is_reported(monkeypatch):
    monkeypatch.setattr(virtualmachine.paths, "is_path_file", lambda path: False)

    assert virtualmachine.get_firmware_pair() is None


def test_the_firmware_variables_are_per_machine():
    # The firmware writes its boot entries into them, so a shared copy would
    # have one machine's entries pointing at another's disk.
    first = virtualmachine.get_boot_firmware_vars("first")
    second = virtualmachine.get_boot_firmware_vars("second")

    assert first != second


def test_a_machine_does_not_write_to_the_distribution_firmware():
    assert not virtualmachine.get_boot_firmware_vars(BOOT_NAME).startswith("/usr/share")


###########################################################
# Paths
###########################################################

def test_a_booted_machine_disk_is_named_after_it():
    assert virtualmachine.get_boot_disk(BOOT_NAME).endswith("%s.qcow2" % BOOT_NAME)


def test_two_booted_machines_do_not_share_a_disk():
    assert virtualmachine.get_boot_disk("first") != virtualmachine.get_boot_disk("second")


def test_a_booted_machine_is_kept_where_it_can_be_written():
    # Not beside the libvirt guests, which are under a directory only root
    # can write to.
    assert not virtualmachine.get_boot_disk(BOOT_NAME).startswith(virtualmachine.IMAGE_DIR)


def test_a_given_directory_is_used_as_it_is():
    assert virtualmachine.get_boot_disk(BOOT_NAME, "/tmp/vms") == "/tmp/vms/llm.qcow2"


###########################################################
# The boot command
###########################################################

def test_an_installer_image_goes_in_the_drive():
    built = boot_command(iso_file = "/images/llm.iso")

    assert any("/images/llm.iso" in str(part) for part in built)
    assert built[built.index("-boot") + 1] == "d"


def test_an_install_stops_when_the_installer_reboots():
    # The image is still in the drive, so firmware that boots it again starts
    # the install over instead of showing what was installed.
    assert "-no-reboot" in boot_command(iso_file = "/images/llm.iso")


def test_booting_the_disk_asks_for_no_image():
    built = boot_command()

    assert "-no-reboot" not in built
    assert "-boot" not in built
    assert "media=cdrom" not in " ".join(str(part) for part in built)


def test_a_machine_boots_the_way_the_target_will():
    # The built in bios cannot boot an efi system partition, so an image that
    # only works under uefi would look broken here for the wrong reason.
    built = " ".join(str(part) for part in boot_command())

    assert "if=pflash" in built
    assert "/fw/code.fd" in built
    assert "/vms/llm-vars.fd" in built


def test_the_firmware_code_is_not_written_to():
    built = boot_command()
    code_drive = [part for part in built if "/fw/code.fd" in str(part)][0]

    assert "readonly=on" in code_drive


def test_a_machine_takes_its_memory_and_processors():
    built = boot_command(memory = 8192, vcpus = 6)

    assert built[built.index("-m") + 1] == "8192M"
    assert built[built.index("-smp") + 1] == "6"


def test_ssh_is_reachable_from_the_workstation():
    built = " ".join(str(part) for part in boot_command(ssh_port = 2345))

    assert "hostfwd=tcp::2345-:22" in built


def test_a_machine_with_no_forwarded_port_gets_no_network():
    built = boot_command(ssh_port = None)

    assert "-net" in built
    assert built[built.index("-net") + 1] == "none"


def test_an_unaccelerated_machine_asks_for_no_acceleration():
    # Asking for kvm without access to it fails to start at all, which is
    # worse than running slowly.
    built = boot_command(accelerated = False)

    assert "accel=kvm" not in " ".join(str(part) for part in built)
    assert "-cpu" not in built


def test_an_accelerated_machine_hands_the_processor_through():
    built = boot_command(accelerated = True)

    assert "accel=kvm" in " ".join(str(part) for part in built)
    assert built[built.index("-cpu") + 1] == "host"


def test_a_headless_machine_opens_no_window():
    built = boot_command(headless = True)

    assert built[built.index("-display") + 1] == "none"


def test_a_headless_machine_can_write_its_console_to_a_file():
    built = boot_command(headless = True, serial_file = "/tmp/console.log")

    assert "file:/tmp/console.log" in [str(part) for part in built]


def test_a_windowed_machine_is_not_made_headless():
    assert "-display" not in boot_command()


###########################################################
# Making a disk
###########################################################

def test_a_blank_disk_is_made_at_the_size_asked_for():
    built = virtualmachine.get_create_boot_disk_command("/vms/llm.qcow2", 40)

    assert "40G" in built
    assert "/vms/llm.qcow2" in built


def test_a_blank_disk_is_sparse():
    # Sixty gigabytes of models has to fit, and a raw disk would cost that
    # much on the workstation before anything was installed.
    built = virtualmachine.get_create_boot_disk_command("/vms/llm.qcow2", 60)

    assert built[built.index("-f") + 1] == "qcow2"


def test_a_blank_disk_is_not_backed_by_anything():
    # Unlike the rehearsal guests, which start from a cloud image; this one
    # is what an installer writes to from nothing.
    built = virtualmachine.get_create_boot_disk_command("/vms/llm.qcow2", 60)

    assert "-b" not in built


###########################################################
# Booting one end to end
#
# What matters is what happens before qemu is reached: a workstation without
# the tools or the firmware has to be told so, rather than finding out after
# a disk has been made.
###########################################################

@pytest.fixture
def bootable(monkeypatch, tmp_path):
    # A workstation with everything a boot needs
    monkeypatch.setattr(virtualmachine, "get_missing_boot_tools", lambda: [])
    monkeypatch.setattr(
        virtualmachine, "get_firmware_pair", lambda pairs = None: ("/fw/code.fd", "/fw/vars.fd"))
    monkeypatch.setattr(virtualmachine, "is_acceleration_available", lambda: True)
    monkeypatch.setattr(
        virtualmachine.fileops, "copy_file_or_directory", lambda **kwargs: True)
    return str(tmp_path / "vms")


def test_a_workstation_without_the_tools_is_told_which(monkeypatch, bootable):
    monkeypatch.setattr(virtualmachine, "get_missing_boot_tools", lambda: ["qemu-img"])

    assert virtualmachine.boot_vm_image(vm_name = BOOT_NAME, boot_dir = bootable) is False


def test_a_workstation_without_firmware_is_told_so(monkeypatch, bootable):
    # Booting without it would fall back to bios and fail for a reason that
    # has nothing to do with the image being tested.
    monkeypatch.setattr(virtualmachine, "get_firmware_pair", lambda pairs = None: None)

    assert virtualmachine.boot_vm_image(vm_name = BOOT_NAME, boot_dir = bootable) is False


def test_an_image_that_is_not_there_stops_before_a_disk_is_made(monkeypatch, bootable):
    recorder = record(monkeypatch)

    assert virtualmachine.boot_vm_image(
        vm_name = BOOT_NAME,
        iso_file = "/images/absent.iso",
        boot_dir = bootable) is False
    assert recorder.calls == []
    assert not os.path.exists(bootable)


def test_a_disk_is_made_before_the_machine_runs(monkeypatch, bootable, tmp_path):
    recorder = record(monkeypatch)
    image = tmp_path / "llm.iso"
    image.write_bytes(b"iso")

    assert virtualmachine.boot_vm_image(
        vm_name = BOOT_NAME, iso_file = str(image), boot_dir = bootable) is True

    assert "qemu-img" in recorder.text(0)
    assert "qemu-system-x86_64" in recorder.text(1)


def test_an_existing_disk_is_not_made_again(monkeypatch, bootable, tmp_path):
    recorder = record(monkeypatch)
    os.makedirs(bootable)
    open(virtualmachine.get_boot_disk(BOOT_NAME, bootable), "wb").close()

    assert virtualmachine.boot_vm_image(vm_name = BOOT_NAME, boot_dir = bootable) is True

    assert len(recorder.calls) == 1
    assert "qemu-system-x86_64" in recorder.text(0)


def test_a_reset_throws_the_disk_away(monkeypatch, bootable, tmp_path):
    record(monkeypatch)
    os.makedirs(bootable)
    disk = virtualmachine.get_boot_disk(BOOT_NAME, bootable)
    with open(disk, "wb") as handle:
        handle.write(b"old")

    virtualmachine.boot_vm_image(vm_name = BOOT_NAME, boot_dir = bootable, reset = True)

    assert not os.path.exists(disk) or open(disk, "rb").read() != b"old"


def test_a_machine_that_will_not_start_is_reported(monkeypatch, bootable):
    record(monkeypatch, returncode = 1)

    assert virtualmachine.boot_vm_image(vm_name = BOOT_NAME, boot_dir = bootable) is False


def test_a_value_given_on_the_command_line_wins(isolated_settings):
    isolated_settings.set_value("UserData.VM", "vm_memory", "2048")

    assert virtualmachine.get_boot_setting("vm_memory", 6144, 8192) == 8192


def test_a_value_not_given_comes_from_the_configuration(isolated_settings):
    isolated_settings.set_value("UserData.VM", "vm_memory", "2048")

    assert virtualmachine.get_boot_setting("vm_memory", 6144) == 2048


def test_zero_is_an_answer_rather_than_an_absent_one(isolated_settings):
    # No forwarded port means no network, which is a thing to ask for.
    assert virtualmachine.get_boot_setting("vm_ssh_port", 2222, 0) == 0
