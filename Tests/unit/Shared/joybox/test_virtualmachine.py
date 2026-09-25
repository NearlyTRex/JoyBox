# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import virtualmachine


###########################################################
# Rehearsal virtual machines
#
# The disposable target the server stack is tried against before a real box.
# Its whole value is that a mistake here costs nothing, so the guest has to be
# reachable after a step that locks ssh, and destroying one must not take
# anything else with it.
###########################################################

NAME = "joybox-test"


def record(monkeypatch, returncode = 0, output = ""):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, returncode = returncode, output = output)


def fake_connection(monkeypatch, **kwargs):
    from fakes import RecordingConnection
    connection = RecordingConnection(**kwargs)
    monkeypatch.setattr(virtualmachine, "get_local_connection", lambda *a, **k: connection)
    return connection


###########################################################
# Prerequisites
###########################################################

def test_every_required_tool_is_named():
    assert set(virtualmachine.REQUIRED_TOOLS) == {
        "virt-install", "virsh", "qemu-img", "cloud-localds"}


def test_a_missing_tool_is_reported(monkeypatch):
    monkeypatch.setattr(
        virtualmachine.command, "is_runnable_command", lambda tool: tool != "virsh")

    assert virtualmachine.get_missing_tools() == ["virsh"]
    assert virtualmachine.are_tools_installed() is False


def test_a_complete_workstation_is_reported_ready(monkeypatch):
    monkeypatch.setattr(
        virtualmachine.command, "is_runnable_command", lambda tool: True)

    assert virtualmachine.get_missing_tools() == []
    assert virtualmachine.are_tools_installed() is True


###########################################################
# Finding a key
###########################################################

def test_an_explicit_key_is_used(tmp_path):
    key = tmp_path / "custom.pub"
    key.write_text("ssh-ed25519 AAAA test\n")

    assert virtualmachine.resolve_ssh_public_key("deploy", str(key)) == str(key)


def test_an_explicit_key_that_is_missing_resolves_to_nothing(tmp_path):
    # Better than silently falling back to a different key than asked for.
    assert virtualmachine.resolve_ssh_public_key(
        "deploy", str(tmp_path / "absent.pub")) is None


def test_an_ed25519_key_is_preferred(monkeypatch):
    # Both are present, and the modern one wins.
    monkeypatch.setattr(virtualmachine.paths, "is_path_file", lambda path: True)

    assert virtualmachine.resolve_ssh_public_key("deploy").endswith("id_ed25519.pub")


def test_an_rsa_key_is_used_when_it_is_the_only_one(monkeypatch):
    monkeypatch.setattr(
        virtualmachine.paths, "is_path_file", lambda path: path.endswith("id_rsa.pub"))

    assert virtualmachine.resolve_ssh_public_key("deploy").endswith("id_rsa.pub")


def test_a_key_is_looked_for_under_the_users_home(monkeypatch):
    seen = []
    monkeypatch.setattr(
        virtualmachine.paths, "is_path_file",
        lambda path: seen.append(path) or False)
    virtualmachine.resolve_ssh_public_key("deploy")

    assert all("/home/deploy/.ssh" in path.replace("\\", "/") for path in seen)


def test_no_key_at_all_resolves_to_nothing(monkeypatch):
    monkeypatch.setattr(virtualmachine.paths, "is_path_file", lambda path: False)

    assert virtualmachine.resolve_ssh_public_key("deploy") is None


###########################################################
# Cloud-init
###########################################################

def user_data(**kwargs):
    defaults = dict(
        vm_name = NAME, username = "deploy",
        ssh_public_key = "ssh-ed25519 AAAA deploy@host")
    defaults.update(kwargs)
    return virtualmachine.build_user_data(**defaults)


def test_the_user_data_declares_itself_as_cloud_config():
    # Without the header cloud-init ignores the file entirely.
    assert user_data().startswith("#cloud-config")


def test_the_guest_takes_the_given_name():
    assert "hostname: %s" % NAME in user_data()


def test_the_public_key_is_authorised():
    assert "ssh-ed25519 AAAA deploy@host" in user_data()


def test_the_user_is_created_with_sudo():
    built = user_data()

    assert "name: deploy" in built
    assert "groups: [sudo]" in built


def test_a_console_password_is_set():
    # The ssh hardening step is one of the things being rehearsed, so locking
    # the key out has to leave a way back in through the console.
    assert "deploy:joybox" in user_data()


def test_the_console_password_can_be_chosen():
    assert "deploy:hunter2" in user_data(console_password = "hunter2")


def test_password_login_is_enabled_at_first_boot():
    assert "ssh_pwauth: true" in user_data()


def test_the_account_is_not_locked():
    assert "lock_passwd: false" in user_data()


def test_ssh_is_installed_and_started():
    built = user_data()

    assert "openssh-server" in built
    assert "systemctl, enable, --now, ssh" in built


def test_the_meta_data_names_the_instance():
    built = virtualmachine.build_meta_data(NAME)

    assert "instance-id: %s" % NAME in built
    assert "local-hostname: %s" % NAME in built


###########################################################
# Image paths
###########################################################

def test_a_guest_disk_is_named_after_it():
    assert virtualmachine.get_disk_image(NAME).endswith("%s.qcow2" % NAME)


def test_a_seed_is_named_after_its_guest():
    assert virtualmachine.get_seed_image(NAME).endswith("%s-seed.iso" % NAME)


def test_the_disk_and_the_seed_are_different_files():
    assert virtualmachine.get_disk_image(NAME) != virtualmachine.get_seed_image(NAME)


def test_two_guests_do_not_share_images():
    assert virtualmachine.get_disk_image("first") != virtualmachine.get_disk_image("second")


def test_the_base_image_is_shared_between_guests():
    # It is the backing file, so a per guest copy would waste the space the
    # copy on write disk exists to save.
    assert virtualmachine.get_base_image("noble") == virtualmachine.get_base_image("noble")


def test_each_release_has_its_own_base_image():
    assert virtualmachine.get_base_image("noble") != virtualmachine.get_base_image("jammy")


def test_the_download_url_matches_the_release():
    assert "noble" in virtualmachine.get_base_image_url("noble")


###########################################################
# Disk creation
###########################################################

def test_a_guest_disk_is_backed_by_the_base_image():
    built = virtualmachine.get_create_disk_command("/img/base.img", "/img/vm.qcow2", 20)

    assert built[built.index("-b") + 1] == "/img/base.img"
    assert "/img/vm.qcow2" in built


def test_a_guest_disk_is_copy_on_write():
    # Without qcow2 on both sides the whole base image is copied per guest.
    built = virtualmachine.get_create_disk_command("/img/base.img", "/img/vm.qcow2", 20)

    assert built[built.index("-f") + 1] == "qcow2"
    assert built[built.index("-F") + 1] == "qcow2"


def test_a_guest_disk_takes_its_size():
    built = virtualmachine.get_create_disk_command("/img/base.img", "/img/vm.qcow2", 40)

    assert "40G" in built


###########################################################
# Installation
###########################################################

def install_command(**kwargs):
    defaults = dict(
        vm_name = NAME, disk_image = "/img/vm.qcow2", seed_image = "/img/seed.iso")
    defaults.update(kwargs)
    return virtualmachine.get_install_command(**defaults)


def test_the_guest_is_installed_by_name():
    built = install_command()

    assert built[built.index("--name") + 1] == NAME


def test_both_disks_are_attached():
    built = " ".join(install_command())

    assert "path=/img/vm.qcow2,device=disk" in built
    assert "path=/img/seed.iso,device=cdrom" in built


def test_the_seed_is_attached_as_a_cdrom():
    # cloud-init looks for its data on removable media.
    built = " ".join(install_command())

    assert "seed.iso,device=cdrom" in built


def test_the_guest_gets_a_network():
    built = install_command()

    assert "network=default,model=virtio" in built


def test_the_install_does_not_take_over_the_terminal():
    # This runs from a script, so it has to return rather than attach.
    built = install_command()

    assert "--noautoconsole" in built
    assert built[built.index("--graphics") + 1] == "none"


def test_an_existing_disk_is_imported_rather_than_installed():
    assert "--import" in install_command()


def test_the_install_targets_the_system_libvirt():
    # Run without root, virt-install would otherwise use the per-user session.
    built = install_command()

    assert built[built.index("--connect") + 1] == "qemu:///system"


def test_virsh_targets_the_system_libvirt():
    assert virtualmachine.get_virsh_command(["list"]) == [
        "virsh", "--connect", "qemu:///system", "list"]


def test_the_console_targets_the_system_libvirt():
    assert virtualmachine.get_console_command(NAME)[1:3] == ["--connect", "qemu:///system"]


def test_the_memory_and_processors_are_passed():
    built = install_command(memory = 8192, vcpus = 4)

    assert built[built.index("--memory") + 1] == "8192"
    assert built[built.index("--vcpus") + 1] == "4"


###########################################################
# Guest state
###########################################################

def test_an_existing_guest_is_found(monkeypatch):
    recorder = record(monkeypatch, returncode = 0)

    assert virtualmachine.does_vm_exist(NAME) is True
    assert recorder.only()[:4] == ["virsh", "--connect", "qemu:///system", "dominfo"]


def test_an_absent_guest_is_not_found(monkeypatch):
    record(monkeypatch, returncode = 1)

    assert virtualmachine.does_vm_exist(NAME) is False


def test_checking_for_a_guest_is_quiet(monkeypatch):
    # Asking about a guest that is not there is a normal question.
    recorder = record(monkeypatch, returncode = 1)
    virtualmachine.does_vm_exist(NAME)

    assert recorder.options().is_output_suppressed() is True


DOMIFADDR = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.50/24
"""


def test_an_address_is_read_from_the_lease(monkeypatch):
    record(monkeypatch, output = DOMIFADDR)

    assert virtualmachine.get_vm_ip(NAME) == "192.168.122.50"


def test_an_address_without_a_lease_is_nothing(monkeypatch):
    record(monkeypatch, output = " Name  MAC address  Protocol  Address\n")

    assert virtualmachine.get_vm_ip(NAME) is None


def test_byte_output_is_decoded(monkeypatch):
    record(monkeypatch, output = DOMIFADDR.encode())

    assert virtualmachine.get_vm_ip(NAME) == "192.168.122.50"


@pytest.mark.parametrize("output", ["", None, "error: failed to get domain"])
def test_unusable_output_yields_no_address(output):
    assert virtualmachine.parse_vm_ip(output) is None


def test_an_ipv6_line_is_not_mistaken_for_an_address():
    output = " vnet0  52:54:00:aa:bb:cc  ipv6  fe80::5054:ff:feaa:bbcc/64\n"

    assert virtualmachine.parse_vm_ip(output) is None


###########################################################
# Base image
###########################################################

def test_the_base_image_is_downloaded_through_sudo(monkeypatch, tmp_path):
    connection = fake_connection(monkeypatch)
    virtualmachine.fetch_base_image(image_dir = str(tmp_path))

    download = [call for call in connection.called("run_return_code") if "curl" in call[1][0]]
    assert download and download[0][2]["sudo"] is True


def test_an_existing_base_image_is_not_downloaded_again(monkeypatch, tmp_path):
    connection = fake_connection(monkeypatch)
    (tmp_path / "noble-server-cloudimg-amd64.img").write_text("")
    virtualmachine.fetch_base_image(image_dir = str(tmp_path))

    assert connection.calls == []


###########################################################
# Snapshots
###########################################################

def test_a_snapshot_is_taken(monkeypatch):
    recorder = record(monkeypatch)

    assert virtualmachine.snapshot_vm(NAME, "pre-sshd") is True
    assert recorder.only()[:5] == ["virsh", "--connect", "qemu:///system", "snapshot-create-as", NAME]
    assert "pre-sshd" in recorder.only()


def test_a_snapshot_can_be_unnamed(monkeypatch):
    recorder = record(monkeypatch)
    virtualmachine.snapshot_vm(NAME)

    assert recorder.only() == ["virsh", "--connect", "qemu:///system", "snapshot-create-as", NAME]


def test_a_named_snapshot_is_reverted_to(monkeypatch):
    recorder = record(monkeypatch)

    assert virtualmachine.revert_vm(NAME, "pre-sshd") is True
    assert recorder.only()[:5] == ["virsh", "--connect", "qemu:///system", "snapshot-revert", NAME]
    assert "pre-sshd" in recorder.only()


def test_reverting_without_a_name_uses_the_current_one(monkeypatch):
    recorder = record(monkeypatch)
    virtualmachine.revert_vm(NAME)

    assert "--current" in recorder.only()


def test_snapshots_are_listed(monkeypatch):
    record(monkeypatch, output = "pre-sshd\npre-docker\n")

    assert virtualmachine.list_snapshots(NAME) == ["pre-sshd", "pre-docker"]


def test_no_snapshots_list_as_empty(monkeypatch):
    record(monkeypatch, output = "")

    assert virtualmachine.list_snapshots(NAME) == []


def test_a_failed_snapshot_is_reported(monkeypatch):
    record(monkeypatch, returncode = 1)

    assert virtualmachine.snapshot_vm(NAME, "pre-sshd") is False


###########################################################
# Destroying
###########################################################

def test_destroying_removes_the_guest_and_its_storage(monkeypatch):
    recorder = record(monkeypatch)
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: True)
    fake_connection(monkeypatch)

    assert virtualmachine.destroy_vm(NAME) is True
    undefine = [call["cmd"] for call in recorder.calls if "undefine" in call["cmd"]][0]
    assert "--remove-all-storage" in undefine


def test_destroying_stops_the_guest_first(monkeypatch):
    # An undefine on a running guest leaves it defined.
    recorder = record(monkeypatch)
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: True)
    fake_connection(monkeypatch)
    virtualmachine.destroy_vm(NAME)
    ordered = [" ".join(call["cmd"]) for call in recorder.calls]

    assert any("destroy" in entry for entry in ordered)
    assert ordered.index([e for e in ordered if "destroy" in e][0]) < \
        ordered.index([e for e in ordered if "undefine" in e][0])


def test_destroying_removes_the_seed(monkeypatch):
    # The seed is not attached storage, so the undefine leaves it behind.
    record(monkeypatch)
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: True)
    connection = fake_connection(monkeypatch)
    virtualmachine.destroy_vm(NAME)

    assert connection.removed_paths and connection.removed_paths[0].endswith("-seed.iso")


def test_the_seed_is_removed_through_sudo(monkeypatch):
    # It sits in libvirt's image directory, which only root can write.
    record(monkeypatch)
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: True)
    connection = fake_connection(monkeypatch)
    virtualmachine.destroy_vm(NAME)

    assert connection.called("remove_file_or_directory")[0][2]["sudo"] is True


def test_destroying_something_absent_is_success(monkeypatch):
    record(monkeypatch)
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: False)

    assert virtualmachine.destroy_vm(NAME) is True


def test_destroying_something_absent_removes_nothing(monkeypatch):
    recorder = record(monkeypatch)
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: False)
    virtualmachine.destroy_vm(NAME)

    assert recorder.ran() is False


###########################################################
# Console
###########################################################

def test_the_console_command_attaches_to_the_guest():
    assert virtualmachine.get_console_command(NAME) == ["virsh", "--connect", "qemu:///system", "console", NAME]


###########################################################
# Refusals
###########################################################

def test_creating_over_an_existing_guest_is_refused(monkeypatch):
    monkeypatch.setattr(virtualmachine, "are_tools_installed", lambda: True)
    monkeypatch.setattr(virtualmachine, "get_missing_tools", lambda: [])
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: True)
    monkeypatch.setattr(virtualmachine.logger, "log_error", lambda *a, **k: None)

    assert virtualmachine.create_vm(NAME) is False


def test_creating_without_the_tools_is_refused(monkeypatch):
    monkeypatch.setattr(virtualmachine, "get_missing_tools", lambda: ["virsh"])
    monkeypatch.setattr(virtualmachine.logger, "log_error", lambda *a, **k: None)

    assert virtualmachine.create_vm(NAME) is False


def test_creating_without_a_key_is_refused(monkeypatch):
    monkeypatch.setattr(virtualmachine, "get_missing_tools", lambda: [])
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: False)
    monkeypatch.setattr(virtualmachine, "resolve_ssh_public_key", lambda *a, **k: None)
    monkeypatch.setattr(virtualmachine.logger, "log_error", lambda *a, **k: None)

    assert virtualmachine.create_vm(NAME, username = "deploy") is False


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
