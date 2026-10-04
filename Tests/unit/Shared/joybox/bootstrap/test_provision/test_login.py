# Local imports
from provision_helpers import SECTION, World, build, fail_on, flat


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


def test_a_failed_account_creation_fails_the_login(entry):
    world = World({"deploy": False, "root": True}, tweak = fail_on(adduser = 1))

    assert build(world).run_login() is False
    assert not any("chpasswd" in flat(cmd) for cmd in world.commands_as("root"))


def test_an_unwritable_password_file_fails_the_login(entry):
    entry.set_value(SECTION, "server_1_pass", "account-secret")
    world = World({"deploy": False, "root": True}, tweak = fail_on(**{"install -m 600 /dev/null": 1}))

    assert build(world).run_login() is False
    commands = [flat(cmd) for cmd in world.commands_as("root")]
    assert any("adduser" in cmd for cmd in commands)
    assert not any("chpasswd" in cmd for cmd in commands)


def test_a_rejected_password_fails_the_login(entry):
    entry.set_value(SECTION, "server_1_pass", "account-secret")
    world = World({"deploy": False, "root": True}, tweak = fail_on(chpasswd = 1))

    assert build(world).run_login() is False


def test_an_account_that_still_cannot_log_in_fails(entry):
    world = World({"deploy": False, "root": True})

    assert build(world).run_login() is False
    assert any("adduser" in flat(cmd) for cmd in world.commands_as("root"))
