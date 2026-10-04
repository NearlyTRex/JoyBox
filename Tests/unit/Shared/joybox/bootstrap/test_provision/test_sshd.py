# Imports
import pytest

# Local imports
from joybox.bootstrap import provision
from provision_helpers import SECTION, World, always_logs_in, build, fail_on, flat


###########################################################
# sshd hardening
#
# The hardening closes root and password login, so the account's key login
# is proven before and after, and a test guest can be reverted.
###########################################################

def test_hardening_is_refused_without_a_working_key_login(entry):
    world = World({"deploy": False, "root": True})

    assert build(world).run_sshd() is False
    assert world.commands_as("root") == []


def test_hardening_already_done_is_skipped(entry):
    world = World({"deploy": True, "root": False})

    assert build(world).run_sshd() is True


def test_hardening_closes_root_login(entry):
    world = World({"deploy": True, "root": True})
    provisioner = build(world)
    original = world.connect

    def connect(username):
        connection = original(username)
        if username == "root":
            original_blocking = connection.run_blocking

            def run_blocking(cmd, sudo = False):
                if "init_sshd.sh" in flat(cmd):
                    world.logins["root"] = False
                return original_blocking(cmd, sudo = sudo)

            connection.run_blocking = run_blocking
        return connection

    provisioner.build_connection = connect

    assert provisioner.run_sshd() is True


def test_root_still_logging_in_afterwards_is_a_failure(entry):
    world = World({"deploy": True, "root": True})

    assert build(world).run_sshd() is False


def test_a_test_guest_that_loses_its_login_is_reverted(entry, monkeypatch):
    entry.set_value(SECTION, "server_1_vm", "joybox-test")
    world = World({"deploy": True, "root": True})
    provisioner = build(world)
    reverted = []
    monkeypatch.setattr(provision.virtualmachine, "delete_snapshot", lambda *a, **k: True)
    monkeypatch.setattr(provision.virtualmachine, "snapshot_vm", lambda *a, **k: True)
    monkeypatch.setattr(provision.virtualmachine, "revert_vm",
                        lambda name, snapshot, **k: reverted.append(snapshot) or True)
    original = world.connect

    def connect(username):
        connection = original(username)
        if username == "root":
            original_blocking = connection.run_blocking

            def run_blocking(cmd, sudo = False):
                if "init_sshd.sh" in flat(cmd):
                    world.logins["deploy"] = False
                return original_blocking(cmd, sudo = sudo)

            connection.run_blocking = run_blocking
        return connection

    provisioner.build_connection = connect

    assert provisioner.run_sshd() is False
    assert reverted == [provision.SNAPSHOT_PRE_SSHD]


def test_hardening_fails_when_root_drops_out_before_it_starts(entry):
    world = World({"deploy": True, "root": False})

    assert always_logs_in(build(world)).run_sshd() is False
    assert world.commands_as("root") == []


def test_hardening_fails_when_the_scripts_cannot_be_shipped(entry):
    world = World({"deploy": True, "root": True}, tweak = fail_on(**{"install -d": 1}))

    assert build(world).run_sshd() is False
    assert not any("init_sshd.sh" in flat(cmd) for cmd in world.commands_as("root"))


def test_a_failed_hardening_script_fails_and_cleans_up(entry):
    world = World({"deploy": True, "root": True}, tweak = fail_on(**{"init_sshd.sh": 1}))

    assert build(world).run_sshd() is False
    assert flat(world.commands_as("root")[-1]).startswith("rm -rf /root/joybox-day0-")


def test_a_real_host_that_loses_its_login_is_not_reverted(entry, monkeypatch):
    monkeypatch.setattr(provision.virtualmachine, "revert_vm", lambda *a, **k: pytest.fail("reverted a real host"))

    def tweak(connection):
        if connection.username == "root":
            original_blocking = connection.run_blocking

            def run_blocking(cmd, sudo = False):
                if "init_sshd.sh" in flat(cmd):
                    world.logins["deploy"] = False
                return original_blocking(cmd, sudo = sudo)
            connection.run_blocking = run_blocking
    world = World({"deploy": True, "root": True}, tweak = tweak)

    assert build(world).run_sshd() is False


def test_a_test_guest_is_snapshotted_before_hardening(guest):
    world = World({"deploy": True, "root": True})

    build(world).run_sshd()

    assert guest[:2] == [("unsnapshot", provision.SNAPSHOT_PRE_SSHD), ("snapshot", provision.SNAPSHOT_PRE_SSHD)]
