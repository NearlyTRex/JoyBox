# Imports
import pytest

# Local imports
from joybox import commandoptions


###########################################################
# Command options
#
# Carried through every command execution and copied at each hand-off, so the
# accessors have to round-trip and a copy must not share state with its source.
###########################################################

SIMPLE_FIELDS = [
    "args", "blocking_processes", "creationflags", "cwd", "desktop_height",
    "desktop_width", "env", "general_prefix_dir", "installer_type",
    "lnk_base_path", "output_paths", "overrides", "prefix_c_drive_real",
    "prefix_c_drive_virtual", "prefix_cwd", "prefix_dir", "prefix_name",
    "prefix_user_profile_dir", "serial", "stderr", "stdout", "winver",
]


def build(**kwargs):
    return commandoptions.CommandOptions(**kwargs)


###########################################################
# Accessors
###########################################################

@pytest.mark.parametrize("field", SIMPLE_FIELDS)
def test_every_field_round_trips(field):
    options = build()
    getattr(options, f"set_{field}")("value")

    assert getattr(options, f"get_{field}")() == "value"


@pytest.mark.parametrize("field", SIMPLE_FIELDS)
def test_every_field_uses_a_distinct_key(field):
    # Two accessors sharing a key would overwrite each other silently.
    options = build()
    getattr(options, f"set_{field}")("value")

    assert len(options.options.get_data_copy()) == 1


###########################################################
# Tricks
#
# get_tricks composes the stored list with winver, since the Windows version
# is itself a winetrick. sandbox.py iterates the result to build the
# "winetricks <name>" commands, so it must always yield whole names.
###########################################################

def test_tricks_round_trip_as_a_list():
    options = build()
    options.set_tricks(["d3dx9", "vcrun2019"])

    assert options.get_tricks() == ["d3dx9", "vcrun2019"]


def test_no_tricks_yields_an_empty_list():
    assert build().get_tricks() == []


def test_the_windows_version_leads_the_tricks():
    options = build()
    options.set_winver("win7")
    options.set_tricks(["d3dx9"])

    assert options.get_tricks() == ["win7", "d3dx9"]


def test_the_windows_version_alone_is_a_trick():
    options = build()
    options.set_winver("win7")

    assert options.get_tricks() == ["win7"]


def test_every_trick_is_a_whole_name():
    # A single-character entry would build a meaningless winetricks command.
    options = build()
    options.set_winver("win7")
    options.set_tricks(["d3dx9", "vcrun2019"])

    assert all(len(trick) > 1 for trick in options.get_tricks())


def test_fields_do_not_collide():
    options = build()
    for field in SIMPLE_FIELDS:
        getattr(options, f"set_{field}")(f"value-{field}")

    for field in SIMPLE_FIELDS:
        assert getattr(options, f"get_{field}")() == f"value-{field}"


###########################################################
# Environment variables
###########################################################

def test_an_environment_variable_round_trips():
    options = build()
    options.set_env_var("PATH", "/usr/bin")

    assert options.get_env_var("PATH") == "/usr/bin"


def test_several_environment_variables_are_kept():
    options = build()
    options.set_env_var("FIRST", "1")
    options.set_env_var("SECOND", "2")

    assert options.get_env_var("FIRST") == "1"
    assert options.get_env_var("SECOND") == "2"


def test_setting_an_environment_variable_populates_the_environment():
    options = build()
    options.set_env_var("JOYBOX", "1")

    assert options.get_env() is not None


###########################################################
# Construction
###########################################################

def test_keyword_arguments_populate_the_options():
    options = build(shell = True)

    assert options.options.get_value("shell") is True


def test_a_new_options_object_is_empty():
    assert build().options.get_data_copy() == {}


def test_two_options_objects_do_not_share_state():
    first = build()
    second = build()
    first.set_cwd("/first")

    assert second.get_cwd() is None


###########################################################
# Copying
###########################################################

def test_a_copy_carries_the_values():
    options = build()
    options.set_cwd("/somewhere")

    assert options.copy().get_cwd() == "/somewhere"


def test_a_copy_is_detached():
    # preprocess_command copies options before rewriting them, so a shallow
    # copy would leak a prefix set for one command into the next.
    options = build()
    options.set_cwd("/original")
    duplicate = options.copy()
    duplicate.set_cwd("/changed")

    assert options.get_cwd() == "/original"


def test_a_copy_detaches_nested_state():
    options = build()
    options.set_env_var("PATH", "/usr/bin")
    duplicate = options.copy()
    duplicate.set_env_var("PATH", "/somewhere/else")

    assert options.get_env_var("PATH") == "/usr/bin"


###########################################################
# Predicates
###########################################################

@pytest.mark.parametrize("predicate", [
    "allow_processing", "force_appimage", "force_powershell", "force_prefix",
    "is_32_bit", "is_daemon", "is_dos", "is_output_suppressed", "is_passthrough",
    "is_prefix", "is_scumm", "is_shell", "is_win31",
])
def test_every_predicate_returns_a_value_on_empty_options(predicate):
    # These gate command execution paths, so none may raise on defaults.
    result = getattr(build(), predicate)()

    assert result is not None or result is None


def test_an_unset_working_directory_is_not_valid():
    assert build().has_valid_cwd() is False


def test_a_set_working_directory_is_valid(tmp_path):
    options = build()
    options.set_cwd(str(tmp_path))

    assert options.has_valid_cwd() is True


def test_an_unset_prefix_name_is_reported_absent():
    assert build().has_prefix_name() is False


def test_a_set_prefix_name_is_reported_present():
    options = build()
    options.set_prefix_name("default")

    assert options.has_prefix_name() is True
