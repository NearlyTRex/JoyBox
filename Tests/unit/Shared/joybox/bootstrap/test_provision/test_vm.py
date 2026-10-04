# Imports
import itertools
import pytest

# Local imports
from joybox.bootstrap import provision
from provision_helpers import SECTION, World, build


###########################################################
# Test guest
###########################################################

def test_a_real_host_has_no_guest_to_build(entry, monkeypatch):
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist",
                        lambda *a, **k: pytest.fail("looked for a guest"))

    assert build(World({})).run_vm() is True


def test_a_guest_built_before_fixed_addresses_is_refused(entry, monkeypatch):
    entry.set_value(SECTION, "server_1_vm", "joybox-test")
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: True)
    monkeypatch.setattr(provision.virtualmachine, "get_vm_interface_mac", lambda *a, **k: "52:54:00:00:00:01")

    assert build(World({})).run_vm() is False


def test_a_new_guest_is_built_at_the_entrys_address(entry, monkeypatch):
    entry.set_value(SECTION, "server_1_vm", "joybox-test")
    created = []
    snapshots = []
    hosts = []
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: False)
    monkeypatch.setattr(provision.virtualmachine, "create_vm",
                        lambda **kwargs: created.append(kwargs) or True)
    monkeypatch.setattr(provision.virtualmachine, "snapshot_vm",
                        lambda name, snapshot, **k: snapshots.append(snapshot) or True)
    monkeypatch.setattr(provision.hostsfile, "set_entries", lambda **kwargs: hosts.append(kwargs) or True)
    world = World({"root": True})

    assert build(world).run_vm() is True
    assert created[0]["address"] == "192.168.122.10"
    assert ["cloud-init", "status", "--wait"] in world.commands_as("root")
    assert snapshots == [provision.SNAPSHOT_FRESH]
    assert hosts[0]["domain"] == "example.com" and hosts[0]["sudo"] is True


def test_a_new_guest_is_waited_on_until_root_can_log_in(entry, monkeypatch):
    # sshd answers before cloud-init has written root's key.
    entry.set_value(SECTION, "server_1_vm", "joybox-test")
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: False)
    monkeypatch.setattr(provision.virtualmachine, "create_vm", lambda **kwargs: True)
    monkeypatch.setattr(provision.virtualmachine, "snapshot_vm", lambda *a, **k: True)
    monkeypatch.setattr(provision.hostsfile, "set_entries", lambda **kwargs: True)
    monkeypatch.setattr(provision.time, "sleep", lambda seconds: None)
    world = World({"root": False})
    provisioner = build(world)
    attempts = []
    original = provisioner.can_log_in

    def can_log_in(username):
        attempts.append(username)
        if len(attempts) == 3:
            world.logins["root"] = True
        return original(username)

    provisioner.can_log_in = can_log_in

    assert provisioner.run_vm() is True
    assert attempts.count("root") >= 3


def test_an_existing_guest_is_started_at_its_address(guest):
    world = World({})

    assert build(world).run_vm() is True
    assert guest[:2] == [("reserve", "192.168.122.10"), ("start", "joybox-test")]
    assert not any(event[0] == "snapshot" for event in guest)
    assert world.connections == []


def test_an_existing_guest_whose_address_cannot_be_reserved_fails(guest, monkeypatch):
    monkeypatch.setattr(provision.virtualmachine, "reserve_address", lambda *a, **k: False)

    assert build(World({})).run_vm() is False
    assert guest == []


def test_a_guest_that_cannot_be_built_fails(guest, monkeypatch):
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: False)
    monkeypatch.setattr(provision.virtualmachine, "create_vm", lambda **kwargs: False)

    assert build(World({})).run_vm() is False


def test_a_new_guest_gets_the_public_key_beside_the_entrys_key(guest, entry, monkeypatch, tmp_path):
    key = tmp_path / "id_ed25519"
    key.write_text("private")
    (tmp_path / "id_ed25519.pub").write_text("public")
    entry.set_value(SECTION, "server_1_key_filepath", str(key))
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: False)

    assert build(World({"root": True})).run_vm() is True
    created = [event[1] for event in guest if event[0] == "create"]
    assert created[0]["ssh_key_file"] == str(key) + ".pub"


def test_a_guest_that_never_answers_fails(guest, monkeypatch):
    clock = itertools.count(0, provision.BOOT_TIMEOUT_SECONDS + 1)
    monkeypatch.setattr(provision.time, "monotonic", lambda: next(clock))
    provisioner = build(World({}))
    provisioner.wait_for_port = lambda host, port: False

    assert provisioner.run_vm() is False
    assert not any(event[0] == "hosts" for event in guest)


def test_a_booting_guest_is_polled_until_it_answers(guest):
    answers = iter([False, False, True])
    provisioner = build(World({}))
    provisioner.wait_for_port = lambda host, port: next(answers)

    assert provisioner.run_vm() is True
    assert any(event[0] == "hosts" for event in guest)


def test_a_new_guest_root_never_accepts_fails(guest, monkeypatch):
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: False)
    provisioner = build(World({"root": False}))
    provisioner.wait_for_login = lambda username, deadline: False

    assert provisioner.run_vm() is False
    assert not any(event[0] == "snapshot" for event in guest)


def test_a_new_guest_refusing_root_after_accepting_fails(guest, monkeypatch):
    monkeypatch.setattr(provision.virtualmachine, "does_vm_exist", lambda *a, **k: False)
    provisioner = build(World({"root": False}))
    provisioner.wait_for_login = lambda username, deadline: True

    assert provisioner.run_vm() is False
    assert not any(event[0] == "snapshot" for event in guest)


def test_a_guest_without_a_domain_leaves_the_hosts_file_alone(guest, entry):
    entry.set_value(SECTION, "server_1_domain_name", "")

    assert build(World({})).run_vm() is True
    assert not any(event[0] == "hosts" for event in guest)
