# Local imports
from provision_helpers import SECTION, World, build, fail_on, flat


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


def test_day0_with_no_login_at_all_fails(entry):
    assert build(World({"deploy": False, "root": False})).run_day0() is False


def test_day0_stops_when_the_scripts_cannot_be_shipped(entry):
    world = World({"root": True}, tweak = fail_on(**{"install -d": 1}))

    assert build(world).run_day0() is False
    assert not any("/scripts/init_" in flat(cmd) for cmd in world.commands_as("root"))


def test_day0_stops_when_the_admin_password_cannot_be_written(entry):
    world = World({"root": True}, tweak = fail_on(**{"/dev/null": 1}))

    assert build(world).run_day0() is False
    commands = [flat(cmd) for cmd in world.commands_as("root")]
    assert not any("/scripts/init_" in cmd for cmd in commands)
    assert commands[-1].startswith("rm -rf /root/joybox-day0-")


def test_day0_stops_when_the_storage_password_cannot_be_written(entry):
    entry.set_value(SECTION, "server_1_storage_user", "u123")
    entry.set_value(SECTION, "server_1_storage_host", "u123.your-storagebox.de")
    entry.set_value(SECTION, "server_1_storage_pass", "box-secret")
    world = World({"root": True}, tweak = fail_on(**{"/dev/null /run/": 1}))

    assert build(world).run_day0() is False
    commands = [flat(cmd) for cmd in world.commands_as("root")]
    assert not any("/scripts/init_" in cmd for cmd in commands)
    assert any(cmd.startswith("rm -f /run/joybox-storage-") for cmd in commands)
    assert commands[-1].startswith("rm -rf /root/joybox-day0-")
