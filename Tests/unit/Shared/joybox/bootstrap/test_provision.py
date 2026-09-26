# Imports
import pytest

# Local imports
from joybox import serverinfo
from joybox.bootstrap import provision
from fakes import RecordingConnection


###########################################################
# Provisioning
#
# One command takes a server entry from nothing to hardened. The same stages
# run against a real host and a test guest, so the rules pinned here are what
# stands between a rehearsal and a locked-out server: the account is proven
# before root is closed, secrets never sit readable, and a rerun resumes.
###########################################################

SECTION = serverinfo.SECTION


@pytest.fixture
def entry(isolated_settings):
    values = {
        "server_1_host": "192.168.122.10",
        "server_1_user": "deploy",
        "server_1_key_filepath": "/home/deploy/.ssh/id_ed25519",
        "server_1_domain_name": "example.com",
        "server_1_htpasswd_pass": "admin-secret",
    }
    for field, value in values.items():
        isolated_settings.set_value(SECTION, field, value)
    return isolated_settings


def server():
    return serverinfo.ServerInfo(1)


class World:
    # Which logins the target accepts, changing as stages run
    def __init__(self, logins):
        self.logins = dict(logins)
        self.connections = []

    def connect(self, username):
        world = self

        class Login(RecordingConnection):
            def try_setup(self, timeout = 15):
                return world.logins.get(username, False)

            def teardown(self):
                pass

        connection = Login()
        connection.username = username
        self.connections.append(connection)
        return connection

    def commands_as(self, username):
        return [cmd for connection in self.connections if connection.username == username
                for cmd in connection.commands]

    def calls_as(self, username):
        return [call for connection in self.connections if connection.username == username
                for call in connection.calls]


def build(world, stages = None, entry_server = None):
    provisioner = provision.Provisioner(
        server = entry_server or server(),
        stages = stages,
        wait_for_port = lambda host, port: True)
    provisioner.build_connection = world.connect
    return provisioner


def flat(cmd):
    return " ".join(cmd)


###########################################################
# Stage order and selection
###########################################################

def test_stages_run_in_the_documented_order():
    assert provision.STAGES == ["vm", "login", "day0", "deploy", "sshd", "verify"]


def test_selected_stages_keep_the_documented_order(entry):
    provisioner = build(World({}), stages = ["verify", "login"])

    assert provisioner.stages == ["login", "verify"]


def test_a_failed_stage_stops_the_run(entry, monkeypatch):
    ran = []
    provisioner = build(World({}), stages = ["login", "day0"])
    monkeypatch.setattr(provisioner, "run_login", lambda: ran.append("login") or False)
    monkeypatch.setattr(provisioner, "run_day0", lambda: ran.append("day0") or True)

    assert provisioner.run() is False
    assert ran == ["login"]


###########################################################
# Missing settings
###########################################################

def test_a_complete_entry_is_missing_nothing(entry):
    assert provision.get_missing_settings(server(), provision.STAGES) == []


def test_day0_needs_the_admin_password(entry):
    entry.set_value(SECTION, "server_1_htpasswd_pass", "")

    assert "server_1_htpasswd_pass" in provision.get_missing_settings(server(), ["day0"])


def test_a_storage_box_needs_its_password(entry):
    entry.set_value(SECTION, "server_1_storage_user", "u123")
    entry.set_value(SECTION, "server_1_storage_host", "u123.your-storagebox.de")

    assert "server_1_storage_pass" in provision.get_missing_settings(server(), ["day0"])


def test_secrets_are_not_needed_for_stages_that_do_not_use_them(entry):
    entry.set_value(SECTION, "server_1_htpasswd_pass", "")

    assert provision.get_missing_settings(server(), ["verify"]) == []


def test_the_key_is_always_needed(entry):
    entry.set_value(SECTION, "server_1_key_filepath", "")

    assert "server_1_key_filepath" in provision.get_missing_settings(server(), ["verify"])


###########################################################
# Commands for the target
###########################################################

def test_the_account_gets_roots_keys_and_the_sudo_group():
    script = provision.build_create_user_command("deploy")[2]

    assert "adduser --disabled-password --gecos '' deploy" in script
    assert "usermod -aG sudo deploy" in script
    assert "/root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys" in script


def test_an_existing_account_is_not_recreated():
    assert "id -u deploy" in provision.build_create_user_command("deploy")[2]


def test_an_account_name_is_quoted():
    script = provision.build_create_user_command("a b")[2]

    assert "'a b'" in script


def test_the_password_file_is_removed_even_when_setting_fails():
    script = provision.build_set_password_command("/root/.secret")[2]

    assert script.index("chpasswd") < script.index("rm -f /root/.secret")
    assert "exit $status" in script


def test_day0_runs_in_order_with_local_storage(entry):
    commands = provision.build_day0_commands(server(), "/d/scripts", {"htpasswd": "/d/h"})

    assert [label for label, _ in commands] == ["sudoers", "docker", "nginx", "htpasswd", "storage"]
    assert commands[-1][1][0] == "/d/scripts/init_localstorage.sh"


def test_day0_mounts_a_storage_box_when_there_is_one(entry):
    entry.set_value(SECTION, "server_1_storage_user", "u123")
    entry.set_value(SECTION, "server_1_storage_host", "u123.your-storagebox.de")
    storage = provision.build_day0_commands(
        server(), "/d/scripts", {"htpasswd": "/d/h", "storage": "/d/s"})[-1][1]

    assert storage[0] == "/d/scripts/init_storagebox.sh"
    assert storage[storage.index("--password-file") + 1] == "/d/s"


def test_the_admin_login_defaults_to_the_account(entry):
    htpasswd = dict(provision.build_day0_commands(server(), "/d", {"htpasswd": "/d/h"}))["htpasswd"]

    assert htpasswd[htpasswd.index("--user") + 1] == "deploy"
    assert htpasswd[htpasswd.index("--password-file") + 1] == "/d/h"


def test_no_secret_is_on_a_command_line(entry):
    entry.set_value(SECTION, "server_1_storage_user", "u123")
    entry.set_value(SECTION, "server_1_storage_host", "u123.your-storagebox.de")
    entry.set_value(SECTION, "server_1_storage_pass", "box-secret")
    commands = provision.build_day0_commands(server(), "/d", {"htpasswd": "/d/h", "storage": "/d/s"})

    assert not any("secret" in flat(cmd) and "/d/" not in flat(cmd) for _, cmd in commands)
    assert not any("admin-secret" in flat(cmd) or "box-secret" in flat(cmd) for _, cmd in commands)


###########################################################
# Login
###########################################################

def test_a_working_login_needs_no_root(entry):
    world = World({"deploy": True, "root": True})

    assert build(world).run_login() is True
    assert world.commands_as("root") == []


def test_the_account_is_created_as_root_on_first_contact(entry):
    world = World({"deploy": False, "root": True})
    provisioner = build(world)
    original = world.connect

    def connect(username):
        connection = original(username)
        if username == "root":
            world.logins["deploy"] = True
        return connection

    provisioner.build_connection = connect

    assert provisioner.run_login() is True
    assert any("adduser" in flat(cmd) for cmd in world.commands_as("root"))


def test_the_account_password_is_set_from_a_private_file(entry):
    entry.set_value(SECTION, "server_1_pass", "account-secret")
    world = World({"deploy": False, "root": True})
    provisioner = build(world)
    original = world.connect
    provisioner.build_connection = lambda username: (
        world.logins.__setitem__("deploy", username == "root" or world.logins["deploy"]) or original(username))

    assert provisioner.run_login() is True
    root_commands = [flat(cmd) for cmd in world.commands_as("root")]
    created = [i for i, cmd in enumerate(root_commands) if cmd.startswith("install -m 600 /dev/null")]
    chpasswd = [i for i, cmd in enumerate(root_commands) if "chpasswd" in cmd]
    assert created and chpasswd and created[0] < chpasswd[0]
    assert not any("account-secret" in cmd for cmd in root_commands)


def test_no_login_at_all_fails(entry):
    assert build(World({"deploy": False, "root": False})).run_login() is False


###########################################################
# Day-0
###########################################################

def test_day0_is_skipped_once_root_login_is_closed(entry):
    world = World({"deploy": True, "root": False})

    assert build(world).run_day0() is True
    assert world.commands_as("root") == []


def test_day0_runs_the_scripts_as_root_and_cleans_up(entry):
    world = World({"deploy": True, "root": True})

    assert build(world).run_day0() is True
    commands = [flat(cmd) for cmd in world.commands_as("root")]
    ran = [cmd.split()[0].rsplit("/", 1)[-1] for cmd in commands if "/scripts/init_" in cmd.split()[0]]
    assert ran == ["init_sudoers.sh", "init_docker.sh", "init_nginx.sh",
                   "init_htpasswd.sh", "init_localstorage.sh"]
    assert commands[-1].startswith("rm -rf /root/joybox-day0-")


def test_day0_ships_this_checkouts_scripts(entry):
    world = World({"deploy": True, "root": True})
    build(world).run_day0()

    sources = [call[1][0] for call in world.calls_as("root") if call[0] == "transfer_files"]
    assert any(source.endswith("/Bootstrap/scripts") for source in sources)
    assert any(source.endswith("/Bootstrap/managers") for source in sources)


def test_the_admin_password_is_written_privately(entry):
    world = World({"deploy": True, "root": True})
    build(world).run_day0()

    calls = world.calls_as("root")
    written = [i for i, call in enumerate(calls) if call[0] == "write_file" and call[1][1] == "admin-secret"]
    locked = [i for i, call in enumerate(calls)
              if call[0] == "run_return_code" and flat(call[1][0]).startswith("install -m 600 /dev/null")]
    assert written and locked and locked[0] < written[0]


def test_a_failed_script_stops_day0_and_still_cleans_up(entry):
    world = World({"deploy": True, "root": True})
    provisioner = build(world)
    original = world.connect

    def connect(username):
        connection = original(username)
        connection.return_codes = {"init_docker.sh": 1}
        return connection

    provisioner.build_connection = connect

    assert provisioner.run_day0() is False
    commands = [flat(cmd) for cmd in world.commands_as("root")]
    assert not any("init_nginx.sh" in cmd for cmd in commands)
    assert commands[-1].startswith("rm -rf /root/joybox-day0-")


###########################################################
# sshd hardening
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


###########################################################
# Verify
###########################################################

def test_verification_runs_as_the_account(entry, monkeypatch):
    world = World({"deploy": True, "root": False})
    seen = []
    monkeypatch.setattr(provision.hardening, "verify_hardening",
                        lambda connection, domain: seen.append((connection.username, domain)) or [])

    assert build(world).run_verify() is True
    assert seen == [("deploy", "example.com")]


def test_failed_checks_are_counted(entry, monkeypatch):
    failure = provision.hardening.CheckResult("sshd", provision.hardening.FAIL, "password login is on")
    monkeypatch.setattr(provision.hardening, "verify_hardening", lambda connection, domain: [failure])
    provisioner = build(World({"deploy": True}))

    assert provisioner.run_verify() is False
    assert provisioner.verify_failures == 1


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


def test_the_storage_password_is_readable_by_the_account_and_removed(entry):
    entry.set_value(SECTION, "server_1_storage_user", "u123")
    entry.set_value(SECTION, "server_1_storage_host", "u123.your-storagebox.de")
    entry.set_value(SECTION, "server_1_storage_pass", "box-secret")
    world = World({"deploy": True, "root": True})

    assert build(world).run_day0() is True
    calls = world.calls_as("root")
    written = [call[1][0] for call in calls if call[0] == "write_file" and call[1][1] == "box-secret"]
    assert written and written[0].startswith("/run/")
    assert ["rm", "-f", written[0]] in world.commands_as("root")
    storage = [cmd for cmd in world.commands_as("root") if cmd and cmd[0].endswith("init_storagebox.sh")][0]
    assert storage[storage.index("--password-file") + 1] == written[0]
