# Third-party imports
import pytest

# Local imports
from joybox import virtualmachine
from vm_helpers import NAME, fake_connection, record


###########################################################
# Rehearsal virtual machines
#
# The disposable target the server stack is tried against before a real box.
# Its whole value is that a mistake here costs nothing, so the guest has to be
# reachable after a step that locks ssh, and destroying one must not take
# anything else with it.
###########################################################

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

    assert virtualmachine.resolve_ssh_public_key(str(key)) == str(key)


def test_an_explicit_key_that_is_missing_resolves_to_nothing(tmp_path):
    # Better than silently falling back to a different key than asked for.
    assert virtualmachine.resolve_ssh_public_key(
        str(tmp_path / "absent.pub")) is None


def test_an_ed25519_key_is_preferred(monkeypatch):
    # Both are present, and the modern one wins.
    monkeypatch.setattr(virtualmachine.paths, "is_path_file", lambda path: True)

    assert virtualmachine.resolve_ssh_public_key().endswith("id_ed25519.pub")


def test_an_rsa_key_is_used_when_it_is_the_only_one(monkeypatch):
    monkeypatch.setattr(
        virtualmachine.paths, "is_path_file", lambda path: path.endswith("id_rsa.pub"))

    assert virtualmachine.resolve_ssh_public_key().endswith("id_rsa.pub")


def test_a_key_is_looked_for_under_the_home_given(monkeypatch):
    seen = []
    monkeypatch.setattr(
        virtualmachine.paths, "is_path_file",
        lambda path: seen.append(path) or False)
    virtualmachine.resolve_ssh_public_key(home_dir = "/home/deploy")

    assert all("/home/deploy/.ssh" in path.replace("\\", "/") for path in seen)


def test_no_key_at_all_resolves_to_nothing(monkeypatch):
    monkeypatch.setattr(virtualmachine.paths, "is_path_file", lambda path: False)

    assert virtualmachine.resolve_ssh_public_key("deploy") is None


###########################################################
# Cloud-init
###########################################################

def user_data(**kwargs):
    defaults = dict(
        vm_name = NAME,
        ssh_public_key = "ssh-ed25519 AAAA deploy@host")
    defaults.update(kwargs)
    return virtualmachine.build_user_data(**defaults)


def test_the_user_data_declares_itself_as_cloud_config():
    # Without the header cloud-init ignores the file entirely.
    assert user_data().startswith("#cloud-config")


def test_the_guest_takes_the_given_name():
    assert "hostname: %s" % NAME in user_data()


def test_the_public_key_is_authorised_for_root():
    # Like a freshly ordered server: root with the key, nothing else.
    built = user_data()

    assert "path: /root/.ssh/authorized_keys" in built
    assert "ssh-ed25519 AAAA deploy@host" in built


def test_the_root_key_is_written_after_cloud_init_manages_keys():
    # Written earlier, cloud-init's own key handling could replace it.
    assert "defer: true" in user_data()


def test_root_keeps_its_key_login():
    assert "disable_root: false" in user_data()


def test_no_account_is_created():
    # Provisioning creates the account, with the grants a real server gets.
    built = user_data()

    assert "users:" not in built
    assert "NOPASSWD" not in built


def test_a_console_password_is_set_for_root():
    # The ssh hardening closes root login, so the console is the way back in.
    assert "root:joybox" in user_data()


def test_the_console_password_can_be_chosen():
    assert "root:hunter2" in user_data(console_password = "hunter2")


def test_password_login_is_enabled_at_first_boot():
    assert "ssh_pwauth: true" in user_data()


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


def test_the_guest_gets_its_fixed_mac():
    built = install_command(mac = "52:54:00:aa:bb:cc")

    assert "network=default,model=virtio,mac=52:54:00:aa:bb:cc" in built


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

    assert virtualmachine.create_vm(NAME) is False


###########################################################
# Fixed address
#
# The server entry names the guest's address once, so the reservation has to
# hold across rebuilds and reverts and never double-book an address.
###########################################################

NETWORK_XML = """<network>
  <name>default</name>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
      <host mac='52:54:00:11:22:33' name='other' ip='192.168.122.20'/>
    </dhcp>
  </ip>
</network>"""


def test_a_guest_keeps_the_same_mac():
    assert virtualmachine.get_vm_mac(NAME) == virtualmachine.get_vm_mac(NAME)


def test_two_guests_get_different_macs():
    assert virtualmachine.get_vm_mac("one") != virtualmachine.get_vm_mac("two")


def test_a_guest_mac_is_in_the_qemu_range():
    assert virtualmachine.get_vm_mac(NAME).startswith("52:54:00:")


def test_reservations_are_read_from_the_network():
    assert virtualmachine.parse_dhcp_hosts(NETWORK_XML) == [
        {"mac": "52:54:00:11:22:33", "name": "other", "ip": "192.168.122.20"}]


def test_unreadable_network_xml_has_no_reservations():
    assert virtualmachine.parse_dhcp_hosts("not xml") == []


def test_a_reservation_that_would_double_book_is_found():
    hosts = virtualmachine.parse_dhcp_hosts(NETWORK_XML)

    assert virtualmachine.get_conflicting_dhcp_hosts(
        hosts, NAME, "52:54:00:aa:bb:cc", "192.168.122.20") == hosts
    assert virtualmachine.get_conflicting_dhcp_hosts(
        hosts, NAME, "52:54:00:aa:bb:cc", "192.168.122.10") == []


def test_the_reservation_is_changed_live_and_persisted():
    built = virtualmachine.get_dhcp_update_command(
        "default", "add-last", "<host mac='m' name='n' ip='i'/>")

    assert built[3:8] == ["net-update", "default", "add-last", "ip-dhcp-host", "<host mac='m' name='n' ip='i'/>"]
    assert "--live" in built and "--config" in built


def test_reserving_adds_the_guest(monkeypatch):
    recorder = record(monkeypatch, output = NETWORK_XML)

    assert virtualmachine.reserve_address(NAME, "192.168.122.10", mac = "52:54:00:aa:bb:cc") is True
    added = [call["cmd"] for call in recorder.calls if "add-last" in call["cmd"]]
    assert added and "ip='192.168.122.10'" in added[0][7]


def test_reserving_replaces_what_held_the_address(monkeypatch):
    recorder = record(monkeypatch, output = NETWORK_XML)
    virtualmachine.reserve_address(NAME, "192.168.122.20", mac = "52:54:00:aa:bb:cc")

    deleted = [call["cmd"] for call in recorder.calls if "delete" in call["cmd"]]
    assert deleted and "name='other'" in deleted[0][7]


def test_an_existing_reservation_is_left_alone(monkeypatch):
    existing = NETWORK_XML.replace(
        "<host mac='52:54:00:11:22:33' name='other' ip='192.168.122.20'/>",
        "<host mac='52:54:00:aa:bb:cc' name='%s' ip='192.168.122.10'/>" % NAME)
    recorder = record(monkeypatch, output = existing)

    assert virtualmachine.reserve_address(NAME, "192.168.122.10", mac = "52:54:00:aa:bb:cc") is True
    assert not [call for call in recorder.calls if "net-update" in call["cmd"]]


###########################################################
# Guest housekeeping
###########################################################

DOMIFLIST = """ Interface   Type      Source    Model    MAC
------------------------------------------------------------
 vnet0       network   default   virtio   52:54:00:CD:E9:CB
"""


def test_the_interface_mac_is_read():
    assert virtualmachine.parse_interface_mac(DOMIFLIST) == "52:54:00:cd:e9:cb"


def test_no_interface_has_no_mac():
    assert virtualmachine.parse_interface_mac("") is None


def test_a_running_guest_is_not_started_again(monkeypatch):
    recorder = record(monkeypatch, output = "running\n")

    assert virtualmachine.start_vm(NAME) is True
    assert not [call for call in recorder.calls if "start" in call["cmd"]]


def test_a_stopped_guest_is_started(monkeypatch):
    recorder = record(monkeypatch, output = "shut off\n")
    virtualmachine.start_vm(NAME)

    assert [call for call in recorder.calls if call["cmd"][3:] == ["start", NAME]]


def test_a_missing_snapshot_needs_no_deleting(monkeypatch):
    recorder = record(monkeypatch, output = "other\n")

    assert virtualmachine.delete_snapshot(NAME, "pre-sshd") is True
    assert not [call for call in recorder.calls if "snapshot-delete" in call["cmd"]]


def test_an_existing_snapshot_is_deleted(monkeypatch):
    recorder = record(monkeypatch, output = "pre-sshd\n")
    virtualmachine.delete_snapshot(NAME, "pre-sshd")

    assert [call for call in recorder.calls if call["cmd"][3:] == ["snapshot-delete", NAME, "pre-sshd"]]
