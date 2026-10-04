# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import commandoptions, config


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
    "prefix_user_profile_dir", "serial", "stderr", "stdin_input", "stdout",
    "winver",
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


def test_setting_an_environment_variable_starts_from_the_process_environment(monkeypatch):
    monkeypatch.setenv("JOYBOX_INHERITED", "kept")
    options = build()
    options.set_env_var("JOYBOX_ADDED", "1")

    assert options.get_env()["JOYBOX_INHERITED"] == "kept"
    assert options.get_env()["JOYBOX_ADDED"] == "1"


def test_an_unset_environment_is_the_process_environment(monkeypatch):
    monkeypatch.setenv("JOYBOX_INHERITED", "kept")

    assert build().get_env()["JOYBOX_INHERITED"] == "kept"


@pytest.mark.parametrize("seed", ["set_env_var", "get_env"])
def test_an_options_environment_never_reaches_the_process_environment(seed):
    # A copy of os.environ still calls putenv on every write, so a variable
    # set for one command would be inherited by every later child process.
    options = build()
    if seed == "set_env_var":
        options.set_env_var("JOYBOX_OPTIONS_ONLY", "kept")

    assert not isinstance(options.get_env(), type(os.environ))
    assert "JOYBOX_OPTIONS_ONLY" not in os.environ


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
    options.set_prefix_name(config.PrefixType.DEFAULT)

    assert options.has_prefix_name() is True


@pytest.mark.parametrize("name", ["Default", "", 0])
def test_only_a_prefix_type_counts_as_a_prefix_name(name):
    # sandbox reads the name back with .val(), so a bare string would crash it.
    options = build()
    options.set_prefix_name(name)

    assert options.has_prefix_name() is False


###########################################################
# Flags
#
# Every one of these changes how a command is launched. Two sharing a key
# would silently turn on a second behaviour along with the one asked for.
###########################################################

FLAGS = [
    ("set_force_appimage", "force_appimage"),
    ("set_force_powershell", "force_powershell"),
    ("set_force_prefix", "force_prefix"),
    ("set_include_stderr", "include_stderr"),
    ("set_is_32_bit", "is_32_bit"),
    ("set_is_daemon", "is_daemon"),
    ("set_is_dos", "is_dos"),
    ("set_is_prefix_mapped_cwd", "is_prefix_mapped_cwd"),
    ("set_is_sandboxie_prefix", "is_sandboxie_prefix"),
    ("set_is_scumm", "is_scumm"),
    ("set_is_shell", "is_shell"),
    ("set_is_win31", "is_win31"),
    ("set_is_wine_prefix", "is_wine_prefix"),
    ("set_passthrough", "is_passthrough"),
    ("set_suppress_output", "is_output_suppressed"),
    ("set_use_virtual_desktop", "use_virtual_desktop"),
]

FLAG_IDS = [getter for _, getter in FLAGS]


@pytest.mark.parametrize("setter,getter", FLAGS, ids = FLAG_IDS)
def test_every_flag_is_off_by_default(setter, getter):
    # A launch option that defaults on would apply to every command.
    assert getattr(build(), getter)() is False


@pytest.mark.parametrize("setter,getter", FLAGS, ids = FLAG_IDS)
def test_every_flag_round_trips(setter, getter):
    options = build()
    getattr(options, setter)(True)

    assert getattr(options, getter)() is True


@pytest.mark.parametrize("setter,getter", FLAGS, ids = FLAG_IDS)
def test_every_flag_can_be_turned_back_off(setter, getter):
    options = build()
    getattr(options, setter)(True)
    getattr(options, setter)(False)

    assert getattr(options, getter)() is False


@pytest.mark.parametrize("setter,getter", FLAGS, ids = FLAG_IDS)
def test_setting_one_flag_leaves_the_others_alone(setter, getter):
    options = build()
    getattr(options, setter)(True)

    for other_setter, other_getter in FLAGS:
        if other_getter == getter:
            continue
        assert getattr(options, other_getter)() is False, \
            "%s also turned on %s" % (setter, other_getter)


def test_every_flag_uses_its_own_key():
    options = build()
    for setter, _ in FLAGS:
        getattr(options, setter)(True)

    assert len(options.options.get_data()) == len(FLAGS)


###########################################################
# Command pre-processing
#
# The odd one out: processing is on unless a caller opts out, because wrapping
# a command for wine or sandboxie is the normal path.
###########################################################

def test_processing_is_allowed_by_default():
    assert build().allow_processing() is True


def test_processing_can_be_turned_off():
    options = build()
    options.set_allow_processing(False)

    assert options.allow_processing() is False


def test_turning_processing_off_leaves_the_other_flags_alone():
    options = build()
    options.set_allow_processing(False)

    for _, getter in FLAGS:
        assert getattr(options, getter)() is False


def test_setting_another_flag_leaves_processing_allowed():
    options = build()
    options.set_is_shell(True)

    assert options.allow_processing() is True


###########################################################
# Prefix kind
###########################################################

def test_a_plain_command_is_not_a_prefix():
    assert build().is_prefix() is False


def test_a_wine_command_is_a_prefix():
    options = build()
    options.set_is_wine_prefix(True)

    assert options.is_prefix() is True


def test_a_sandboxie_command_is_a_prefix():
    options = build()
    options.set_is_sandboxie_prefix(True)

    assert options.is_prefix() is True


def test_the_two_prefix_kinds_are_independent():
    # Nothing stops both being set; the callers branch on wine first.
    options = build()
    options.set_is_wine_prefix(True)

    assert options.is_sandboxie_prefix() is False


###########################################################
# Desktop dimensions
###########################################################

def test_the_dimensions_join_width_and_height():
    options = build()
    options.set_desktop_width(1024)
    options.set_desktop_height(768)

    assert options.get_desktop_dimensions() == "1024x768"


def test_the_dimensions_fall_back_to_the_settings(isolated_settings):
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_w", "1920")
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_h", "1080")

    assert build().get_desktop_dimensions() == "1920x1080"


def test_an_explicit_width_overrides_the_settings(isolated_settings):
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_w", "1920")
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_h", "1080")
    options = build()
    options.set_desktop_width(800)

    assert options.get_desktop_dimensions() == "800x1080"


def test_a_zero_width_falls_back(isolated_settings):
    # Zero is not a resolution, so it reads as unset.
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_w", "1920")
    options = build()
    options.set_desktop_width(0)

    assert options.get_desktop_width() == "1920"


###########################################################
# Blocking processes
###########################################################

def test_no_blocking_processes_is_an_empty_list():
    assert build().get_blocking_processes() == []


def test_a_blocking_process_is_added_from_a_string():
    options = build()
    options.add_blocking_processes("dolphin")

    assert options.get_blocking_processes() == ["dolphin"]


def test_blocking_processes_are_added_from_a_list():
    options = build()
    options.add_blocking_processes(["dolphin", "cemu"])

    assert options.get_blocking_processes() == ["dolphin", "cemu"]


def test_adding_keeps_what_was_there():
    # Each layer of the launch stack adds its own; replacing would let an
    # emulator keep running while its saves are copied.
    options = build()
    options.set_blocking_processes(["wine"])
    options.add_blocking_processes("dolphin")

    assert options.get_blocking_processes() == ["wine", "dolphin"]


def test_adding_twice_accumulates():
    options = build()
    options.add_blocking_processes("wine")
    options.add_blocking_processes("dolphin")

    assert options.get_blocking_processes() == ["wine", "dolphin"]


def test_adding_something_unsupported_changes_nothing():
    options = build()
    options.set_blocking_processes(["wine"])
    options.add_blocking_processes(None)

    assert options.get_blocking_processes() == ["wine"]


def test_no_output_paths_is_an_empty_list():
    assert build().get_output_paths() == []


def test_creationflags_default_to_none_set():
    assert build().get_creationflags() == 0


###########################################################
# Derived prefix paths
#
# Each is composed from a stored root, and returns nothing when that root was
# never set rather than building a path against None.
###########################################################

PROFILE_DERIVED = [
    "get_prefix_user_profile_gamedata_dir",
    "get_prefix_user_profile_registry_dir",
]

C_DRIVE_DERIVED = [
    "get_prefix_dos_c_drive",
    "get_prefix_dos_d_drive",
    "get_prefix_scumm_dir",
]


@pytest.mark.parametrize("accessor", PROFILE_DERIVED + C_DRIVE_DERIVED)
def test_a_derived_path_without_its_root_is_nothing(accessor):
    assert getattr(build(), accessor)() is None


@pytest.mark.parametrize("accessor", PROFILE_DERIVED)
def test_a_profile_derived_path_sits_under_the_profile(accessor):
    options = build()
    options.set_prefix_user_profile_dir("/prefix/drive_c/users/deploy")

    assert getattr(options, accessor)().startswith("/prefix/drive_c/users/deploy")


@pytest.mark.parametrize("accessor", C_DRIVE_DERIVED)
def test_a_drive_derived_path_sits_under_the_c_drive(accessor):
    options = build()
    options.set_prefix_c_drive_real("/prefix/drive_c")

    assert getattr(options, accessor)().startswith("/prefix/drive_c")


def test_the_profile_derived_paths_are_distinct():
    options = build()
    options.set_prefix_user_profile_dir("/prefix/users/deploy")

    assert options.get_prefix_user_profile_gamedata_dir() != \
        options.get_prefix_user_profile_registry_dir()


def test_the_dos_drives_are_distinct():
    # C and D are separate mounts inside the dos tree.
    options = build()
    options.set_prefix_c_drive_real("/prefix/drive_c")

    assert options.get_prefix_dos_c_drive() != options.get_prefix_dos_d_drive()


def test_the_dos_drives_share_a_parent():
    options = build()
    options.set_prefix_c_drive_real("/prefix/drive_c")

    assert os.path.dirname(options.get_prefix_dos_c_drive()) == \
        os.path.dirname(options.get_prefix_dos_d_drive())


def test_the_scumm_directory_is_not_inside_the_dos_tree():
    options = build()
    options.set_prefix_c_drive_real("/prefix/drive_c")

    assert not options.get_prefix_scumm_dir().startswith(
        os.path.dirname(options.get_prefix_dos_c_drive()))


@pytest.mark.parametrize("accessor,setter", [
    ("has_valid_prefix_dos_c_drive", "set_prefix_c_drive_real"),
    ("has_valid_prefix_dos_d_drive", "set_prefix_c_drive_real"),
    ("has_valid_prefix_scumm_dir", "set_prefix_c_drive_real"),
])
def test_a_derived_path_is_only_valid_once_its_root_is_set(accessor, setter):
    options = build()
    assert getattr(options, accessor)() is False

    getattr(options, setter)("/prefix/drive_c")
    assert getattr(options, accessor)() is True


###########################################################
# Path predicates
###########################################################

PATH_FIELDS = [
    ("prefix_dir", "has_valid_prefix_dir", "has_existing_prefix_dir"),
    ("general_prefix_dir", "has_valid_general_prefix_dir",
     "has_existing_general_prefix_dir"),
    ("prefix_user_profile_dir", "has_valid_prefix_user_profile_dir",
     "has_existing_prefix_user_profile_dir"),
    ("prefix_c_drive_real", "has_valid_prefix_c_drive_real",
     "has_existing_prefix_c_drive_real"),
]


@pytest.mark.parametrize("field,valid,existing", PATH_FIELDS)
def test_an_unset_path_is_neither_valid_nor_existing(field, valid, existing):
    options = build()

    assert getattr(options, valid)() is False
    assert getattr(options, existing)() is False


@pytest.mark.parametrize("field,valid,existing", PATH_FIELDS)
def test_a_path_can_be_valid_without_existing(field, valid, existing, tmp_path):
    # Validity is about the shape of the path; the prefix is created later.
    options = build()
    getattr(options, "set_" + field)(str(tmp_path / "not-created-yet"))

    assert getattr(options, valid)() is True
    assert getattr(options, existing)() is False


@pytest.mark.parametrize("field,valid,existing", PATH_FIELDS)
def test_an_existing_path_is_both(field, valid, existing, tmp_path):
    options = build()
    getattr(options, "set_" + field)(str(tmp_path))

    assert getattr(options, valid)() is True
    assert getattr(options, existing)() is True


def test_the_virtual_c_drive_is_valid_once_set():
    options = build()
    assert options.has_valid_prefix_c_drive_virtual() is False

    options.set_prefix_c_drive_virtual("C:\\")
    assert options.has_valid_prefix_c_drive_virtual() is True


def test_an_unset_prefix_working_directory_is_not_valid():
    assert build().has_valid_prefix_cwd() is False


###########################################################
# Prefix working directory
#
# A prefix command starts inside the prefix's C drive, so the host working
# directory follows the prefix one once the drive exists.
###########################################################

def test_the_working_directory_follows_the_prefix_working_directory(tmp_path):
    (tmp_path / "Games" / "Doom").mkdir(parents = True)
    options = build(cwd = "/host/elsewhere")
    options.set_prefix_c_drive_real(str(tmp_path))
    options.set_prefix_cwd(os.path.join("Games", "Doom"))

    options.sync_cwd_to_prefix_cwd()

    assert options.get_cwd() == os.path.realpath(str(tmp_path / "Games" / "Doom"))


def test_the_working_directory_stays_without_a_prefix_working_directory(tmp_path):
    options = build(cwd = "/host/elsewhere")
    options.set_prefix_c_drive_real(str(tmp_path))

    options.sync_cwd_to_prefix_cwd()

    assert options.get_cwd() == "/host/elsewhere"


def test_the_working_directory_stays_until_the_c_drive_exists(tmp_path):
    options = build(cwd = "/host/elsewhere")
    options.set_prefix_c_drive_real(str(tmp_path / "not-created-yet"))
    options.set_prefix_cwd("Games")

    options.sync_cwd_to_prefix_cwd()

    assert options.get_cwd() == "/host/elsewhere"


###########################################################
# Ready prefix
###########################################################

def ready_options(tmp_path):
    return build(
        is_wine_prefix = True,
        prefix_name = config.PrefixType.GAME,
        prefix_dir = str(tmp_path))


def test_a_named_existing_wine_prefix_is_ready(tmp_path):
    assert ready_options(tmp_path).has_ready_prefix() is True


def test_a_native_command_has_no_ready_prefix(tmp_path):
    options = ready_options(tmp_path)
    options.set_is_wine_prefix(False)

    assert options.has_ready_prefix() is False


def test_an_unnamed_prefix_is_not_ready(tmp_path):
    options = ready_options(tmp_path)
    options.set_prefix_name(None)

    assert options.has_ready_prefix() is False


def test_a_prefix_that_does_not_exist_yet_is_not_ready(tmp_path):
    options = ready_options(tmp_path)
    options.set_prefix_dir(str(tmp_path / "not-created-yet"))

    assert options.has_ready_prefix() is False


###########################################################
# Prefix setup
###########################################################

@pytest.fixture
def sandbox_dirs(monkeypatch, tmp_path):
    from joybox import programs
    roots = {"Wine": str(tmp_path / "wine"), "Sandboxie": str(tmp_path / "sandboxie")}
    monkeypatch.setattr(programs, "get_tool_path_config_value", lambda tool, key: roots[tool])
    return roots


def test_setting_up_a_wine_prefix_names_its_directory_after_the_prefix(sandbox_dirs):
    options = build()

    options.setup_prefix(
        is_wine_prefix = True,
        is_sandboxie_prefix = False,
        prefix_name = config.PrefixType.TOOL)

    assert options.is_wine_prefix() is True
    assert options.is_sandboxie_prefix() is False
    assert options.get_prefix_name() == config.PrefixType.TOOL
    assert options.get_prefix_dir() == os.path.join(sandbox_dirs["Wine"], "Tool")


def test_setting_up_a_sandboxie_prefix_uses_the_sandboxie_root(sandbox_dirs):
    options = build()

    options.setup_prefix(
        is_wine_prefix = False,
        is_sandboxie_prefix = True,
        prefix_name = config.PrefixType.GAME)

    assert options.get_prefix_dir() == os.path.join(sandbox_dirs["Sandboxie"], "Game")


def test_an_explicit_prefix_directory_wins(sandbox_dirs):
    options = build()

    options.setup_prefix(
        is_wine_prefix = True,
        is_sandboxie_prefix = False,
        prefix_name = config.PrefixType.TOOL,
        prefix_dir = "/explicit/prefix",
        general_prefix_dir = "/explicit/general")

    assert options.get_prefix_dir() == "/explicit/prefix"
    assert options.get_general_prefix_dir() == "/explicit/general"


def test_a_native_setup_leaves_the_prefix_directory_unset(sandbox_dirs):
    options = build()

    options.setup_prefix(
        is_wine_prefix = False,
        is_sandboxie_prefix = False,
        prefix_name = config.PrefixType.TOOL)

    assert options.get_prefix_dir() is None
    assert options.get_general_prefix_dir() is None


###########################################################
# Prefix creation
###########################################################

@pytest.fixture
def fake_sandbox(monkeypatch, tmp_path):
    from joybox import sandbox
    state = {"calls": [], "result": True, "profile": tmp_path / "profile", "c_drive": tmp_path / "drive_c"}
    state["profile"].mkdir()
    state["c_drive"].mkdir()

    def create(kind):
        def run(options, **kwargs):
            state["calls"].append((kind, kwargs))
            return state["result"]
        return run

    monkeypatch.setattr(sandbox, "create_basic_prefix", create("basic"))
    monkeypatch.setattr(sandbox, "create_linked_prefix", create("linked"))
    monkeypatch.setattr(sandbox, "get_user_profile_path", lambda options: str(state["profile"]))
    monkeypatch.setattr(sandbox, "get_real_c_drive_path", lambda options: str(state["c_drive"]))
    return state


def create(options, **kwargs):
    return options.create_prefix(
        is_wine_prefix = True,
        is_sandboxie_prefix = False,
        prefix_name = config.PrefixType.GAME,
        prefix_dir = "/prefixes/game",
        **kwargs)


def test_creating_a_prefix_records_its_profile_and_drives(fake_sandbox):
    options = build()

    assert create(options) is True
    assert options.get_prefix_user_profile_dir() == str(fake_sandbox["profile"])
    assert options.get_prefix_c_drive_real() == str(fake_sandbox["c_drive"])
    assert options.get_prefix_c_drive_virtual() == config.drive_root_windows


def test_a_basic_prefix_is_created_unless_a_linked_one_is_asked_for(fake_sandbox):
    create(build())
    create(build(), linked_prefix = True, other_links = ["/shared"])

    assert [kind for kind, _ in fake_sandbox["calls"]] == ["basic", "linked"]
    assert fake_sandbox["calls"][1][1]["other_links"] == ["/shared"]


@pytest.mark.parametrize("linked", [False, True])
def test_prefix_creation_passes_the_run_flags_through(fake_sandbox, linked):
    create(build(), linked_prefix = linked, clean_existing = False,
        verbose = True, pretend_run = True, exit_on_failure = True)

    _, kwargs = fake_sandbox["calls"][0]
    assert kwargs["clean_existing"] is False
    assert kwargs["verbose"] is True
    assert kwargs["pretend_run"] is True
    assert kwargs["exit_on_failure"] is True


@pytest.mark.parametrize("linked", [False, True])
def test_a_failed_creation_is_reported(fake_sandbox, linked):
    fake_sandbox["result"] = False

    assert create(build(), linked_prefix = linked) is False


def test_a_prefix_without_a_profile_is_not_created(fake_sandbox):
    fake_sandbox["profile"].rmdir()

    assert create(build()) is False


def test_a_prefix_without_a_c_drive_is_not_created(fake_sandbox):
    fake_sandbox["c_drive"].rmdir()

    assert create(build()) is False
