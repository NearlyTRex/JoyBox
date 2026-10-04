# Imports
import pytest

# Local imports
from joybox import computer, config
from computer_helpers import TOKEN_MAP, PLAIN_ACCESSORS, program


###########################################################
# Program
#
# One entry of a computer game's launch list, read straight out of the game
# json. Paths carry tokens that are only expanded against a prefix's token map.
###########################################################

###########################################################
# Accessors
###########################################################

@pytest.mark.parametrize("setter,getter,value", PLAIN_ACCESSORS)
def test_every_field_round_trips(setter, getter, value):
    entry = program(**{setter: value})

    assert getattr(entry, getter)() == value


@pytest.mark.parametrize("setter,getter,value", PLAIN_ACCESSORS)
def test_every_field_uses_a_distinct_key(setter, getter, value):
    entry = program(**{setter: value})

    assert len(entry.get_data()) == 1


def test_all_fields_together_do_not_collide():
    entry = computer.Program()
    for setter, getter, value in PLAIN_ACCESSORS:
        getattr(entry, "set_" + setter)(value)

    assert len(entry.get_data()) == len(PLAIN_ACCESSORS)
    for setter, getter, value in PLAIN_ACCESSORS:
        assert getattr(entry, getter)() == value


@pytest.mark.parametrize("accessor,default", [
    ("get_args", []),
    ("get_tricks", []),
    ("get_overrides", []),
    ("is_shell", False),
    ("is_daemon", False),
    ("is_32_bit", False),
    ("is_dos", False),
    ("is_win31", False),
    ("is_scumm", False),
])
def test_an_unset_field_has_a_usable_default(accessor, default):
    # run() reads all of these unconditionally, so a None default would break
    # the launch path.
    assert getattr(computer.Program(), accessor)() == default


@pytest.mark.parametrize("accessor,default", [
    ("get_env", None),
    ("get_winver", None),
    ("get_desktop", None),
    ("get_installer_type", None),
    ("get_serial", None),
])
def test_an_unset_optional_field_is_absent(accessor, default):
    assert getattr(computer.Program(), accessor)() is default


@pytest.mark.parametrize("setter,checker", [
    ("set_is_shell", "is_shell"),
    ("set_is_daemon", "is_daemon"),
    ("set_is_32_bit", "is_32_bit"),
    ("set_is_dos", "is_dos"),
    ("set_is_win31", "is_win31"),
    ("set_is_scumm", "is_scumm"),
])
def test_every_flag_round_trips(setter, checker):
    entry = computer.Program()
    getattr(entry, setter)(True)

    assert getattr(entry, checker)() is True


def test_flags_do_not_share_a_key():
    entry = computer.Program()
    entry.set_is_dos(True)

    assert entry.is_win31() is False
    assert entry.is_scumm() is False
    assert entry.is_shell() is False


def test_a_program_is_built_from_existing_json():
    entry = computer.Program({config.program_key_exe: "game.exe"})

    assert entry.get_exe() == "game.exe"


def test_an_empty_program_holds_nothing():
    assert computer.Program().get_data() == {}


###########################################################
# Path resolution
###########################################################

def test_an_exe_round_trips():
    assert program(exe = "game.exe").get_exe() == "game.exe"


def test_a_cwd_round_trips():
    assert program(cwd = "Game").get_cwd() == "Game"


def test_an_exe_token_is_expanded():
    # get_cwd already does this; an exe path carries the same tokens and must
    # expand the same way.
    entry = program(exe = "$GAME_INSTALL_DIR/game.exe")

    assert entry.get_exe(TOKEN_MAP) == "/prefix/drive_c/Game/game.exe"


def test_a_cwd_token_is_expanded():
    entry = program(cwd = "$GAME_INSTALL_DIR")

    assert entry.get_cwd(TOKEN_MAP) == "/prefix/drive_c/Game"


@pytest.mark.parametrize("accessor", ["get_exe", "get_cwd"])
def test_a_path_without_tokens_is_unchanged(accessor):
    entry = program(exe = "game.exe", cwd = "Game")

    assert getattr(entry, accessor)(TOKEN_MAP) == getattr(entry, accessor)()


@pytest.mark.parametrize("accessor", ["get_exe", "get_cwd"])
def test_no_token_map_leaves_the_path_alone(accessor):
    entry = program(exe = "$GAME_INSTALL_DIR/game.exe", cwd = "$GAME_INSTALL_DIR")

    assert "$GAME_INSTALL_DIR" in getattr(entry, accessor)()


@pytest.mark.parametrize("accessor", ["get_exe", "get_cwd"])
def test_an_unset_path_stays_unset(accessor):
    assert getattr(computer.Program(), accessor)(TOKEN_MAP) is None


def test_every_token_in_a_path_is_expanded():
    entry = program(exe = "$GAME_INSTALL_DIR/$GAME_SAVE_DIR")

    assert entry.get_exe(TOKEN_MAP) == "/prefix/drive_c/Game//prefix/saves"


def test_an_unknown_token_is_left_in_place():
    entry = program(exe = "$NOT_A_TOKEN/game.exe")

    assert entry.get_exe(TOKEN_MAP) == "$NOT_A_TOKEN/game.exe"


def test_resolving_does_not_rewrite_the_stored_path():
    # The json is the source of truth; resolution is per launch.
    entry = program(exe = "$GAME_INSTALL_DIR/game.exe")
    entry.get_exe(TOKEN_MAP)

    assert entry.get_exe() == "$GAME_INSTALL_DIR/game.exe"
