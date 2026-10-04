# Imports
import pytest

# Local imports
from joybox import computer, config
from computer_helpers import PLAIN_ACCESSORS, TOKEN_MAP, step


###########################################################
# ProgramStep
###########################################################

@pytest.mark.parametrize("setter,getter,value", [
    ("from", "get_from", "install/data"),
    ("to", "get_to", "$GAME_INSTALL_DIR/data"),
    ("dir", "get_dir", "$GAME_INSTALL_DIR"),
    ("type", "get_type", "copy"),
])
def test_every_step_field_round_trips(setter, getter, value):
    entry = step(**{setter: value})

    assert getattr(entry, getter)() == value


def test_step_fields_do_not_collide():
    entry = step(**{"from": "a", "to": "b", "dir": "c", "type": "copy"})

    assert len(entry.get_data()) == 4
    assert entry.get_from() == "a"
    assert entry.get_to() == "b"
    assert entry.get_dir() == "c"


@pytest.mark.parametrize("accessor", ["get_from", "get_to", "get_dir"])
def test_an_unset_step_path_is_an_empty_string(accessor):
    # run() passes these straight to sandbox.resolve_path, which indexes into
    # the string.
    assert getattr(computer.ProgramStep(), accessor)() == ""


def test_an_unset_step_type_is_absent():
    assert computer.ProgramStep().get_type() is None


@pytest.mark.parametrize("setter,checker", [
    ("set_skip_existing", "skip_existing"),
    ("set_skip_identical", "skip_identical"),
])
def test_every_step_flag_round_trips(setter, checker):
    entry = computer.ProgramStep()
    getattr(entry, setter)(True)

    assert getattr(entry, checker)() is True


@pytest.mark.parametrize("checker", ["skip_existing", "skip_identical"])
def test_step_flags_default_to_off(checker):
    assert getattr(computer.ProgramStep(), checker)() is False


def test_step_flags_do_not_share_a_key():
    entry = computer.ProgramStep()
    entry.set_skip_existing(True)

    assert entry.skip_identical() is False


def test_a_step_is_built_from_existing_json():
    entry = computer.ProgramStep({config.program_step_key_type: "extract"})

    assert entry.get_type() == "extract"


def test_an_empty_step_holds_nothing():
    assert computer.ProgramStep().get_data() == {}


def test_a_program_and_a_step_do_not_share_keys():
    # Both are read from the same game json; a shared key would let one clobber
    # the other's value.
    entry = computer.Program()
    for setter, getter, value in PLAIN_ACCESSORS:
        getattr(entry, "set_" + setter)(value)
    entry.set_exe("game.exe")
    entry.set_cwd("Game")

    step_entry = step(**{"from": "a", "to": "b", "dir": "c", "type": "copy"})
    step_entry.set_skip_existing(True)
    step_entry.set_skip_identical(True)

    assert not (set(entry.get_data()) & set(step_entry.get_data()))


###########################################################
# Running a step
#
# Install steps shuffle files around a prefix whose case is not reliable, so
# paths are matched without regard to case.
###########################################################

@pytest.fixture
def actions(monkeypatch):
    calls = []
    for owner, name in [
        (computer.fileops, "smart_copy"),
        (computer.fileops, "smart_move"),
        (computer.archive, "extract_archive"),
        (computer.fileops, "lowercase_all_paths"),
    ]:
        monkeypatch.setattr(
            owner, name, lambda _name = name, **kwargs: calls.append((_name, kwargs)) or "result")
    return calls


def full_step(kind):
    entry = step(**{"from": "$GAME_INSTALL_DIR/a", "to": "$GAME_SAVE_DIR/b",
                    "dir": "$GAME_INSTALL_DIR", "type": kind})
    entry.set_skip_existing(True)
    entry.set_skip_identical(True)
    return entry


@pytest.mark.parametrize("kind,action", [
    ("copy", "smart_copy"),
    ("move", "smart_move"),
])
def test_a_transfer_step_resolves_both_ends(actions, kind, action):
    assert full_step(kind).run(TOKEN_MAP, verbose = True) == "result"
    name, kwargs = actions[0]

    assert name == action
    assert kwargs["src"] == "/prefix/drive_c/Game/a"
    assert kwargs["dest"] == "/prefix/saves/b"
    assert kwargs["skip_existing"] is True
    assert kwargs["skip_identical"] is True
    assert kwargs["case_sensitive_paths"] is False
    assert kwargs["verbose"] is True


def test_an_extract_step_unpacks_into_the_target(actions):
    assert full_step("extract").run(TOKEN_MAP, pretend_run = True) == "result"
    name, kwargs = actions[0]

    assert name == "extract_archive"
    assert kwargs["archive_file"] == "/prefix/drive_c/Game/a"
    assert kwargs["extract_dir"] == "/prefix/saves/b"
    assert kwargs["skip_existing"] is True
    assert kwargs["pretend_run"] is True


def test_a_lowercase_step_works_on_its_directory(actions):
    assert full_step("lowercase").run(TOKEN_MAP, exit_on_failure = True) == "result"

    assert actions == [("lowercase_all_paths", {
        "src": "/prefix/drive_c/Game", "verbose": False,
        "pretend_run": False, "exit_on_failure": True})]


@pytest.mark.parametrize("kind", [None, "unknown"])
def test_an_unknown_step_does_nothing(actions, kind):
    assert full_step(kind).run(TOKEN_MAP) is True
    assert actions == []
