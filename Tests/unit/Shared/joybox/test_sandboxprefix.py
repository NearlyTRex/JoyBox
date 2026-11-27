# Imports
import getpass
import os

# Third-party imports
import pytest

# Local imports
from joybox import commandoptions, commandrun, config, sandbox, sandboxprefix
from joybox import prefixlayout


###########################################################
# Creating a wine prefix
#
# Each command runs as an argv list with no shell, so a trick has to be an
# argument to winetricks, never part of the program name.
###########################################################

TOOLS = {"WineBoot": "/tools/wineboot", "WineTricks": "/tools/winetricks", "WineServer": "/tools/wineserver"}


@pytest.fixture
def ran(monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: TOOLS[name])
    monkeypatch.setattr(commandrun, "run_prepared_returncode_command",
                        lambda cmd, **kwargs: commands.append(cmd) or 0)
    return commands


def build(tmp_path, tricks):
    options = commandoptions.CommandOptions()
    options.set_is_wine_prefix(True)
    options.set_prefix_dir(str(tmp_path / "prefix"))
    options.set_tricks(tricks)
    return options


def test_tricks_are_arguments_to_winetricks(ran, tmp_path):
    assert sandboxprefix.create_wine_prefix(build(tmp_path, ["d3dx9", "vcrun2019"]))

    assert ["/tools/winetricks", "d3dx9", "vcrun2019"] in ran


def test_no_tricks_runs_only_wineboot(ran, tmp_path):
    assert sandboxprefix.create_wine_prefix(build(tmp_path, []))

    assert ran == [["/tools/wineboot"]]


def test_wine_prefix_creation_stops_at_the_first_failing_command(monkeypatch, tmp_path):
    ran = []
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: TOOLS[name])
    monkeypatch.setattr(commandrun, "run_prepared_returncode_command", lambda cmd, **kwargs: ran.append(cmd) or 1)

    assert sandboxprefix.create_wine_prefix(build(tmp_path, ["d3dx9"])) is False
    assert ran == [["/tools/wineboot"]]


def test_wine_prefix_creation_fails_when_its_directory_cannot_be_made(ran, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox.fileops, "make_directory", lambda **kwargs: False)

    assert sandboxprefix.create_wine_prefix(build(tmp_path, [])) is False
    assert ran == []


def test_wine_prefix_commands_run_against_the_new_prefix(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: TOOLS[name])
    monkeypatch.setattr(commandrun, "run_prepared_returncode_command",
                        lambda cmd, options, **kwargs: seen.append(options.get_env()) or 0)

    sandboxprefix.create_wine_prefix(build(tmp_path, []))

    assert seen[0]["WINEPREFIX"] == str(tmp_path / "prefix")


###########################################################
# Creating a sandboxie prefix
###########################################################

def sandboxie(tmp_path):
    options = commandoptions.CommandOptions()
    options.set_is_sandboxie_prefix(True)
    options.set_prefix_dir(str(tmp_path / "box"))
    options.set_prefix_name(config.PrefixType.GAME)
    return options


@pytest.fixture
def sandboxie_tools(monkeypatch):
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: "/tools/" + name)


def test_a_sandboxie_prefix_lays_out_its_drive_and_profile(sandboxie_tools, recording_command, tmp_path):
    assert sandboxprefix.create_sandboxie_prefix(sandboxie(tmp_path)) is True

    assert (tmp_path / "box" / "drive" / "C").is_dir()
    assert (tmp_path / "box" / "user" / "current").is_dir()


def test_a_sandboxie_box_is_configured_by_name(sandboxie_tools, recording_command, tmp_path):
    sandboxprefix.create_sandboxie_prefix(sandboxie(tmp_path))

    commands = [call["cmd"] for call in recording_command.calls]
    assert ["/tools/SandboxieIni", "set", "Game", "Enabled", "y"] in commands
    assert ["/tools/SandboxieIni", "set", "Game", "FileRootPath", str(tmp_path / "box")] in commands
    assert all(call["options"].is_sandboxie_prefix() for call in recording_command.calls)
    assert all(call["options"].is_shell() for call in recording_command.calls)


def test_a_sandboxie_setting_that_fails_fails_the_prefix(sandboxie_tools, recording_command, tmp_path):
    recording_command.returncode = 1

    assert sandboxprefix.create_sandboxie_prefix(sandboxie(tmp_path)) is False
    assert len(recording_command.calls) == 1


def test_a_sandboxie_prefix_fails_when_a_folder_cannot_be_made(sandboxie_tools, recording_command, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox.fileops, "make_directory", lambda **kwargs: False)

    assert sandboxprefix.create_sandboxie_prefix(sandboxie(tmp_path)) is False
    assert recording_command.calls == []


###########################################################
# Basic prefixes
###########################################################

@pytest.fixture
def created(monkeypatch):
    kinds = []
    monkeypatch.setattr(sandboxprefix, "create_wine_prefix", lambda **kwargs: kinds.append("wine") or True)
    monkeypatch.setattr(sandboxprefix, "create_sandboxie_prefix", lambda **kwargs: kinds.append("sandboxie") or True)
    return kinds


def wine(tmp_path):
    options = build(tmp_path, [])
    options.set_general_prefix_dir(str(tmp_path / "general"))
    return options


def test_a_basic_prefix_needs_a_directory(created):
    assert sandboxprefix.create_basic_prefix(commandoptions.CommandOptions()) is False
    assert created == []


def test_a_basic_wine_prefix_replaces_an_existing_one(created, tmp_path):
    stale = tmp_path / "prefix" / "stale.txt"
    stale.parent.mkdir()
    stale.write_text("")

    assert sandboxprefix.create_basic_prefix(wine(tmp_path)) is True
    assert not stale.exists()
    assert created == ["wine"]


def test_a_basic_prefix_can_keep_what_is_there(created, tmp_path):
    kept = tmp_path / "prefix" / "kept.txt"
    kept.parent.mkdir()
    kept.write_text("")

    sandboxprefix.create_basic_prefix(wine(tmp_path), clean_existing = False)

    assert kept.exists()


def test_a_basic_prefix_fails_when_the_old_one_cannot_be_removed(created, tmp_path, monkeypatch):
    (tmp_path / "prefix").mkdir()
    monkeypatch.setattr(sandbox.fileops, "remove_object", lambda **kwargs: False)

    assert sandboxprefix.create_basic_prefix(wine(tmp_path)) is False
    assert created == []


def test_a_basic_wine_prefix_fails_when_wine_does(monkeypatch, tmp_path):
    monkeypatch.setattr(sandboxprefix, "create_wine_prefix", lambda **kwargs: False)

    assert sandboxprefix.create_basic_prefix(wine(tmp_path)) is False


def test_a_basic_wine_prefix_unlinks_the_profile_from_the_host(created, tmp_path):
    # Wine links Documents and friends to the host home; saves must stay inside.
    profile = tmp_path / "prefix" / "drive_c" / "users" / getpass.getuser()
    profile.mkdir(parents = True)
    host = tmp_path / "host_documents"
    host.mkdir()
    os.symlink(str(host), str(profile / "Documents"))

    assert sandboxprefix.create_basic_prefix(wine(tmp_path), clean_existing = False) is True
    assert (profile / "Documents").is_dir()
    assert not (profile / "Documents").is_symlink()


def test_a_basic_sandboxie_prefix_is_created(created, tmp_path):
    assert sandboxprefix.create_basic_prefix(sandboxie(tmp_path)) is True
    assert created == ["sandboxie"]


def test_a_basic_sandboxie_prefix_fails_when_sandboxie_does(monkeypatch, tmp_path):
    monkeypatch.setattr(sandboxprefix, "create_sandboxie_prefix", lambda **kwargs: False)

    assert sandboxprefix.create_basic_prefix(sandboxie(tmp_path)) is False


def test_a_basic_prefix_of_neither_kind_is_not_created(created, tmp_path):
    options = commandoptions.CommandOptions()
    options.set_prefix_dir(str(tmp_path / "prefix"))

    assert sandboxprefix.create_basic_prefix(options) is False


###########################################################
# Linked prefixes
#
# A linked prefix points its user profile at a shared general prefix, so saves
# from every game land in one place.
###########################################################

def test_a_linked_prefix_needs_both_directories(created, tmp_path):
    no_general = build(tmp_path, [])

    assert sandboxprefix.create_linked_prefix(commandoptions.CommandOptions()) is False
    assert sandboxprefix.create_linked_prefix(no_general) is False
    assert created == []


def test_a_linked_prefix_needs_a_prefix_kind(created, tmp_path):
    options = commandoptions.CommandOptions()
    options.set_prefix_dir(str(tmp_path / "prefix"))
    options.set_general_prefix_dir(str(tmp_path / "general"))

    assert sandboxprefix.create_linked_prefix(options) is False


def test_a_linked_wine_prefix_points_its_profile_at_the_general_prefix(created, tmp_path):
    options = wine(tmp_path)

    assert sandboxprefix.create_linked_prefix(options) is True

    profile = prefixlayout.get_wine_user_profile_path(options)
    assert os.path.realpath(profile) == str(tmp_path / "general")
    for folder in config.computer_user_folders:
        assert (tmp_path / "general" / folder).is_dir()


def test_a_linked_prefix_links_its_other_paths(created, tmp_path):
    source = tmp_path / "shared_data"
    source.mkdir()
    links = [{"from": str(source), "to": "Data"}, {"from": str(tmp_path / "absent"), "to": "Absent"}]

    assert sandboxprefix.create_linked_prefix(wine(tmp_path), other_links = links) is True

    c_drive = tmp_path / "prefix" / "drive_c"
    assert os.path.realpath(str(c_drive / "Data")) == str(source)
    assert not os.path.lexists(str(c_drive / "Absent"))


def test_a_linked_sandboxie_prefix_is_created(created, tmp_path):
    options = sandboxie(tmp_path)
    options.set_general_prefix_dir(str(tmp_path / "general"))

    assert sandboxprefix.create_linked_prefix(options, clean_existing = False) is True
    assert created == ["sandboxie"]


def test_a_linked_prefix_fails_when_the_old_one_cannot_be_removed(created, tmp_path, monkeypatch):
    (tmp_path / "prefix").mkdir()
    monkeypatch.setattr(sandbox.fileops, "remove_object", lambda **kwargs: False)

    assert sandboxprefix.create_linked_prefix(wine(tmp_path)) is False
    assert created == []


def test_a_linked_prefix_fails_when_a_general_folder_cannot_be_made(created, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox.fileops, "make_directory", lambda **kwargs: False)

    assert sandboxprefix.create_linked_prefix(wine(tmp_path)) is False
    assert created == []


def test_a_linked_wine_prefix_fails_when_wine_does(monkeypatch, tmp_path):
    monkeypatch.setattr(sandboxprefix, "create_wine_prefix", lambda **kwargs: False)

    assert sandboxprefix.create_linked_prefix(wine(tmp_path)) is False


def test_a_linked_sandboxie_prefix_fails_when_sandboxie_does(monkeypatch, tmp_path):
    monkeypatch.setattr(sandboxprefix, "create_sandboxie_prefix", lambda **kwargs: False)
    options = sandboxie(tmp_path)
    options.set_general_prefix_dir(str(tmp_path / "general"))

    assert sandboxprefix.create_linked_prefix(options) is False


def test_a_linked_prefix_fails_when_its_profile_cannot_be_linked(created, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox.fileops, "create_symlink", lambda **kwargs: False)

    assert sandboxprefix.create_linked_prefix(wine(tmp_path)) is False


def test_a_linked_prefix_fails_when_another_path_cannot_be_linked(created, tmp_path, monkeypatch):
    source = tmp_path / "shared_data"
    source.mkdir()
    links = []
    monkeypatch.setattr(sandbox.fileops, "create_symlink", lambda **kwargs: links.append(kwargs) or len(links) == 1)

    assert sandboxprefix.create_linked_prefix(
        wine(tmp_path), other_links = [{"from": str(source), "to": "Data"}]) is False
    assert len(links) == 2


###########################################################
# Prefix creation
###########################################################

@pytest.fixture
def fake_sandbox(monkeypatch, tmp_path):
    state = {"calls": [], "result": True, "profile": tmp_path / "profile", "c_drive": tmp_path / "drive_c"}
    state["profile"].mkdir()
    state["c_drive"].mkdir()

    def create(kind):
        def run(options, **kwargs):
            state["calls"].append((kind, kwargs))
            return state["result"]
        return run

    monkeypatch.setattr(sandboxprefix, "create_basic_prefix", create("basic"))
    monkeypatch.setattr(sandboxprefix, "create_linked_prefix", create("linked"))
    monkeypatch.setattr(prefixlayout, "get_user_profile_path", lambda options: str(state["profile"]))
    monkeypatch.setattr(prefixlayout, "get_real_c_drive_path", lambda options: str(state["c_drive"]))
    return state


def create(options, **kwargs):
    return sandboxprefix.create_prefix(
        options = options,
        is_wine_prefix = True,
        is_sandboxie_prefix = False,
        prefix_name = config.PrefixType.GAME,
        prefix_dir = "/prefixes/game",
        **kwargs)


def test_creating_a_prefix_records_its_profile_and_drives(fake_sandbox):
    options = commandoptions.CommandOptions()

    assert create(options) is True
    assert options.get_prefix_user_profile_dir() == str(fake_sandbox["profile"])
    assert options.get_prefix_c_drive_real() == str(fake_sandbox["c_drive"])
    assert options.get_prefix_c_drive_virtual() == config.DRIVE_ROOT_WINDOWS


def test_a_basic_prefix_is_created_unless_a_linked_one_is_asked_for(fake_sandbox):
    create(commandoptions.CommandOptions())
    create(commandoptions.CommandOptions(), linked_prefix = True, other_links = ["/shared"])

    assert [kind for kind, _ in fake_sandbox["calls"]] == ["basic", "linked"]
    assert fake_sandbox["calls"][1][1]["other_links"] == ["/shared"]


@pytest.mark.parametrize("linked", [False, True])
def test_prefix_creation_passes_the_run_flags_through(fake_sandbox, linked):
    create(commandoptions.CommandOptions(), linked_prefix = linked, clean_existing = False,
        verbose = True, pretend_run = True, exit_on_failure = True)

    _, kwargs = fake_sandbox["calls"][0]
    assert kwargs["clean_existing"] is False
    assert kwargs["verbose"] is True
    assert kwargs["pretend_run"] is True
    assert kwargs["exit_on_failure"] is True


@pytest.mark.parametrize("linked", [False, True])
def test_a_failed_creation_is_reported(fake_sandbox, linked):
    fake_sandbox["result"] = False

    assert create(commandoptions.CommandOptions(), linked_prefix = linked) is False


def test_a_prefix_without_a_profile_is_not_created(fake_sandbox):
    fake_sandbox["profile"].rmdir()

    assert create(commandoptions.CommandOptions()) is False


def test_a_prefix_without_a_c_drive_is_not_created(fake_sandbox):
    fake_sandbox["c_drive"].rmdir()

    assert create(commandoptions.CommandOptions()) is False


###########################################################
# Cleaning up after a command
###########################################################

def test_wine_cleanup_stops_the_wine_server(recording_command, monkeypatch):
    killed = []
    monkeypatch.setattr(sandboxprefix.programs, "get_tool_program", lambda name: "/tools/" + name)
    monkeypatch.setattr(sandboxprefix.process, "kill_active_named_processes", killed.append)

    sandboxprefix.cleanup_wine(pretend_run = True)

    assert recording_command.only() == ["/tools/WineServer", "-k"]
    assert recording_command.calls[0]["kwargs"]["pretend_run"] is True
    assert recording_command.calls[0]["options"].is_shell()
    assert killed == [["/tools/WineServer"]]
