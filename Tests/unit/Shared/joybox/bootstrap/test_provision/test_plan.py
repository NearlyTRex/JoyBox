# Local imports
from joybox.bootstrap import provision
from provision_helpers import SECTION, World, build, flat, server


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


def test_every_passing_stage_completes_the_run(entry, monkeypatch):
    ran = []
    provisioner = build(World({}), stages = ["login", "verify"])
    monkeypatch.setattr(provisioner, "run_login", lambda: ran.append("login") or True)
    monkeypatch.setattr(provisioner, "run_verify", lambda: ran.append("verify") or True)

    assert provisioner.run() is True
    assert ran == ["login", "verify"]


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


def test_deploy_and_verify_need_the_domain(entry):
    entry.set_value(SECTION, "server_1_domain_name", "")

    assert provision.get_missing_settings(server(), ["deploy"]) == ["server_1_domain_name"]


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
# Describing the run
###########################################################

def test_describe_names_a_real_host(entry):
    lines = build(World({}), stages = ["login"]).describe()

    assert lines == [
        "Provisioning server 1 (deploy@192.168.122.10)",
        "  stages: login",
        "  components: all",
        "  storage: local",
    ]


def test_describe_names_a_guest_its_components_and_storage_box(entry):
    entry.set_value(SECTION, "server_1_vm", "joybox-test")
    entry.set_value(SECTION, "server_1_storage_user", "u123")
    entry.set_value(SECTION, "server_1_storage_host", "u123.your-storagebox.de")
    provisioner = build(World({}))
    provisioner.components = ["nginx", "gitea"]

    lines = provisioner.describe()

    assert "  test guest: joybox-test" in lines
    assert "  components: nginx, gitea" in lines
    assert "  storage: Storage Box u123.your-storagebox.de" in lines
