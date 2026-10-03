# Third-party imports
import pytest

# Local imports
from joybox import virtualmachine
from vm_helpers import NAME, fake_connection, record


###########################################################
# Building a guest end to end
#
# Everything root-only goes through the connection and everything virsh goes
# through the command runner, so both are faked and nothing reaches libvirt.
###########################################################

KEY = "ssh-ed25519 AAAA deploy@workstation"


@pytest.fixture
def creatable(monkeypatch, tmp_path):
    # A workstation with the tools, a key, a base image and no guest yet
    monkeypatch.setattr(virtualmachine, "get_missing_tools", lambda: [])
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: False)
    monkeypatch.setattr(virtualmachine.logger, "log_error", lambda *a, **k: None)
    monkeypatch.setattr(virtualmachine.logger, "log_info", lambda *a, **k: None)
    key = tmp_path / "id_ed25519.pub"
    key.write_text(KEY + "\n")
    images = tmp_path / "images"
    images.mkdir()
    (images / "noble-server-cloudimg-amd64.img").write_text("")
    seed_dir = tmp_path / "seed"
    monkeypatch.setattr(
        virtualmachine.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(seed_dir)))
    removed = []
    monkeypatch.setattr(
        virtualmachine.fileops, "remove_directory",
        lambda src, **kwargs: removed.append(src) or True)

    class World:
        pass
    world = World()
    world.key = str(key)
    world.images = str(images)
    world.seed_dir = seed_dir
    world.removed = removed
    world.connection = fake_connection(monkeypatch)
    world.command = record(monkeypatch)
    return world


def create(world, **kwargs):
    return virtualmachine.create_vm(
        NAME, ssh_key_file = world.key, image_dir = world.images, **kwargs)


def test_a_guest_is_created(creatable):
    assert create(creatable) is True

    assert creatable.connection.ran("qemu-img", "create", NAME + ".qcow2")
    assert creatable.connection.ran("cloud-localds", NAME + "-seed.iso")
    assert all(call[2]["sudo"] for call in creatable.connection.called("run_return_code"))
    assert creatable.command.calls[-1]["cmd"][0] == "virt-install"


def test_the_seed_carries_the_key_and_the_name(creatable):
    create(creatable)

    assert KEY in (creatable.seed_dir / "user-data").read_text()
    assert "instance-id: %s" % NAME in (creatable.seed_dir / "meta-data").read_text()
    assert creatable.removed == [str(creatable.seed_dir)]


def test_the_address_is_reserved_before_the_install(creatable):
    create(creatable)

    commands = [call["cmd"] for call in creatable.command.calls]
    reserve = [i for i, cmd in enumerate(commands) if "add-last" in cmd]
    forget = [i for i, cmd in enumerate(commands) if cmd[:2] == ["ssh-keygen", "-R"]]
    assert reserve and forget
    assert reserve[0] < forget[0] < len(commands) - 1
    assert "ip='%s'" % virtualmachine.DEFAULT_ADDRESS in commands[reserve[0]][7]


def test_a_guest_without_an_address_is_not_reserved_one(creatable):
    assert create(creatable, address = None) is True

    assert not [call for call in creatable.command.calls if "net-update" in call["cmd"]]
    assert not [call for call in creatable.command.calls if call["cmd"][0] == "ssh-keygen"]


def test_an_empty_key_file_is_refused(creatable):
    with open(creatable.key, "w"):
        pass

    assert create(creatable) is False
    assert creatable.connection.calls == []


def test_a_base_image_that_cannot_be_fetched_stops_the_build(monkeypatch, creatable):
    monkeypatch.setattr(virtualmachine, "fetch_base_image", lambda **kwargs: None)

    assert create(creatable) is False
    assert creatable.connection.calls == []


def test_a_disk_that_cannot_be_made_stops_the_build(creatable):
    creatable.connection.return_codes["qemu-img"] = 1

    assert create(creatable) is False
    assert not creatable.connection.ran("cloud-localds")


def test_no_seed_directory_stops_the_build(monkeypatch, creatable):
    monkeypatch.setattr(
        virtualmachine.fileops, "create_temporary_directory", lambda **kwargs: (False, None))

    assert create(creatable) is False
    assert not creatable.connection.ran("cloud-localds")


def test_a_seed_file_that_cannot_be_written_stops_the_build(monkeypatch, creatable):
    monkeypatch.setattr(virtualmachine.fileops, "touch_file", lambda **kwargs: False)

    assert create(creatable) is False
    assert not creatable.connection.ran("cloud-localds")
    assert creatable.removed == [str(creatable.seed_dir)]


def test_a_failed_seed_is_cleaned_up(creatable):
    creatable.connection.return_codes["cloud-localds"] = 1

    assert create(creatable) is False
    assert creatable.removed == [str(creatable.seed_dir)]
    assert creatable.command.calls == []


def test_a_failed_reservation_stops_the_install(monkeypatch, creatable):
    monkeypatch.setattr(virtualmachine, "reserve_address", lambda **kwargs: False)

    assert create(creatable) is False
    assert not [call for call in creatable.command.calls if call["cmd"][0] == "virt-install"]


def test_a_failed_install_is_reported(creatable):
    creatable.command.returncode = 1

    assert create(creatable, address = None) is False


###########################################################
# Base image download failures
###########################################################

def test_an_image_dir_that_cannot_be_made_fetches_nothing(monkeypatch, tmp_path):
    connection = fake_connection(monkeypatch)
    monkeypatch.setattr(connection, "make_directory", lambda src, sudo = False: False)

    assert virtualmachine.fetch_base_image(image_dir = str(tmp_path / "images")) is None
    assert connection.commands == []


def test_a_failed_download_fetches_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(virtualmachine.logger, "log_info", lambda *a, **k: None)
    fake_connection(monkeypatch, return_codes = {"curl": 22})

    assert virtualmachine.fetch_base_image(image_dir = str(tmp_path)) is None


def test_a_download_names_the_image_it_fetched(monkeypatch, tmp_path):
    monkeypatch.setattr(virtualmachine.logger, "log_info", lambda *a, **k: None)
    connection = fake_connection(monkeypatch)

    assert virtualmachine.fetch_base_image(image_dir = str(tmp_path)) == virtualmachine.get_base_image(
        image_dir = str(tmp_path))
    assert connection.ran("curl", "--proto =https", "https://cloud-images.ubuntu.com/noble/")


def test_the_local_connection_carries_the_flags():
    connection = virtualmachine.get_local_connection(
        verbose = True, pretend_run = True, exit_on_failure = True)

    assert connection.flags.verbose is True
    assert connection.flags.pretend_run is True
    assert connection.flags.exit_on_failure is True


###########################################################
# Network
###########################################################

NET_INFO_ACTIVE = """Name:           default
UUID:           0d0f5c8a-0000-0000-0000-000000000000
Active:         yes
Persistent:     yes
Autostart:      yes
Bridge:         virbr0
"""

NET_INFO_INACTIVE = """Name:           default
Active:         no
Persistent:     yes
Autostart:      no
Bridge:         virbr0
"""


def test_an_active_network_is_left_alone(monkeypatch):
    recorder = record(monkeypatch, output = NET_INFO_ACTIVE.encode())

    assert virtualmachine.start_network() is True
    assert recorder.only()[3:] == ["net-info", "default"]


def test_a_persistent_but_stopped_network_is_started(monkeypatch):
    # Persistent: yes must not be read as running.
    recorder = record(monkeypatch, output = NET_INFO_INACTIVE)
    virtualmachine.start_network()

    assert [call["cmd"][3:] for call in recorder.calls[1:]] == [
        ["net-start", "default"], ["net-autostart", "default"]]


@pytest.mark.parametrize("output", [None, "", "error: network not found", NET_INFO_INACTIVE])
def test_a_network_not_reported_active_is_not_active(output):
    assert virtualmachine.is_network_active(output) is False


def test_a_network_reported_active_is_active():
    assert virtualmachine.is_network_active(NET_INFO_ACTIVE) is True


###########################################################
# Reservations
###########################################################

DNS_NETWORK_XML = """<network>
  <name>default</name>
  <dns>
    <host ip='192.168.122.10'><hostname>alias</hostname></host>
  </dns>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <host mac='52:54:00:11:22:33' name='other' ip='192.168.122.20'/>
    </dhcp>
  </ip>
  <ip family='ipv6' address='fd00::1' prefix='64'>
    <dhcp>
      <host id='0:3:0:1:0:16:3e:11:22:33' name='six' ip='fd00::20'/>
    </dhcp>
  </ip>
</network>"""


def test_dns_entries_are_not_reservations():
    assert virtualmachine.parse_dhcp_hosts(DNS_NETWORK_XML) == [
        {"mac": "52:54:00:11:22:33", "name": "other", "ip": "192.168.122.20"},
        {"name": "six", "ip": "fd00::20"},
    ]


def test_empty_network_xml_has_no_reservations():
    assert virtualmachine.parse_dhcp_hosts("") == []


def test_a_conflicting_ipv6_entry_can_be_replaced(monkeypatch):
    recorder = record(monkeypatch, output = DNS_NETWORK_XML.encode())

    assert virtualmachine.reserve_address("six", "192.168.122.10", mac = "52:54:00:aa:bb:cc") is True
    deleted = [call["cmd"][7] for call in recorder.calls if "delete" in call["cmd"]]
    assert deleted == ["<host name='six' ip='fd00::20'/>"]


def test_a_failed_reservation_is_reported(monkeypatch):
    monkeypatch.setattr(virtualmachine.logger, "log_error", lambda *a, **k: None)
    record(monkeypatch, returncode = 1, output = "")

    assert virtualmachine.reserve_address(NAME, "192.168.122.10") is False


def test_a_reservation_defaults_to_the_guest_mac(monkeypatch):
    recorder = record(monkeypatch, output = "")
    virtualmachine.reserve_address(NAME, "192.168.122.10")

    assert "mac='%s'" % virtualmachine.get_vm_mac(NAME) in recorder.calls[-1]["cmd"][7]


def test_forgetting_a_host_key_is_quiet(monkeypatch):
    recorder = record(monkeypatch)
    virtualmachine.forget_host_key("192.168.122.10")

    assert recorder.only() == ["ssh-keygen", "-R", "192.168.122.10"]
    assert recorder.options().is_output_suppressed()


###########################################################
# Guest housekeeping
###########################################################

def test_a_running_guest_reported_as_bytes_is_not_started_again(monkeypatch):
    recorder = record(monkeypatch, output = b"running\n")

    assert virtualmachine.start_vm(NAME) is True
    assert len(recorder.calls) == 1


def test_a_guest_that_will_not_start_is_reported(monkeypatch):
    record(monkeypatch, returncode = 1, output = "shut off\n")

    assert virtualmachine.start_vm(NAME) is False


def test_the_interface_mac_is_read_from_virsh(monkeypatch):
    recorder = record(monkeypatch, output = b" vnet0  network  default  virtio  52:54:00:CD:E9:CB\n")

    assert virtualmachine.get_vm_interface_mac(NAME) == "52:54:00:cd:e9:cb"
    assert recorder.only()[3:] == ["domiflist", NAME]


def test_a_guest_without_an_interface_has_no_mac(monkeypatch):
    record(monkeypatch, output = "")

    assert virtualmachine.get_vm_interface_mac(NAME) is None


def test_an_interface_list_without_a_mac_has_none():
    assert virtualmachine.parse_interface_mac(" Interface   Type\n---\n") is None


def test_an_ipv4_line_without_an_address_yields_none():
    assert virtualmachine.parse_vm_ip(" vnet0  52:54:00:aa:bb:cc  ipv4  pending\n") is None


def test_snapshots_reported_as_bytes_are_listed(monkeypatch):
    record(monkeypatch, output = b"pre-sshd\n\npost-sshd\n")

    assert virtualmachine.list_snapshots(NAME) == ["pre-sshd", "post-sshd"]


def test_a_failed_undefine_is_reported_and_keeps_the_seed(monkeypatch):
    monkeypatch.setattr(virtualmachine, "does_vm_exist", lambda *a, **k: True)
    connection = fake_connection(monkeypatch)
    record(monkeypatch, returncode = 1)

    assert virtualmachine.destroy_vm(NAME) is False
    assert connection.removed_paths == []
