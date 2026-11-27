# Imports
import types

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import programcatalog
from joybox import programsetup


###########################################################
# Setup steps from program data
#
# A program's setup is the list of steps in its program.toml. The runner adds
# the name, dirs, locker and run flags each kind needs, so a wrong added
# argument installs into the wrong place for every program at once.
###########################################################

PARAMS = types.SimpleNamespace(verbose = True, pretend_run = False, exit_on_failure = False, locker_type = "LOCKER", skip_autobackup = True)


@pytest.fixture
def setup_world(monkeypatch):
    state = {"steps": [], "calls": [], "results": {}, "needs_install": set(), "gates": [], "errors": []}

    def steps(family, name, offline = False):
        state["asked"] = (family, name, offline)
        return [dict(step) for step in state["steps"]]
    monkeypatch.setattr(programcatalog, "get_setup_steps", steps)

    def should_program_be_installed(name, platform = None):
        state["gates"].append(("program", name, platform))
        return (name, platform) in state["needs_install"]
    def should_library_be_installed(name, platform = None):
        state["gates"].append(("library", name, platform))
        return (name, "library") in state["needs_install"]
    programs = programsetup.programs
    monkeypatch.setattr(programs, "should_program_be_installed", should_program_be_installed)
    monkeypatch.setattr(programs, "should_library_be_installed", should_library_be_installed)
    monkeypatch.setattr(programs, "get_program_install_dir", lambda name, platform = None: "/tools/%s/%s" % (name, platform))
    monkeypatch.setattr(programs, "get_program_backup_dir", lambda name, platform = None: "/backups/%s/%s" % (name, platform))
    monkeypatch.setattr(programs, "get_library_install_dir", lambda name, platform = None: "/libs/%s/%s" % (name, platform))
    monkeypatch.setattr(programs, "get_library_backup_dir", lambda name, platform = None: "/libbackups/%s/%s" % (name, platform))
    monkeypatch.setattr(programs, "get_tool_config_value", lambda name, key: "tool:%s:%s" % (name, key))
    monkeypatch.setattr(programs, "get_emulator_config_value", lambda name, key: "emulator:%s:%s" % (name, key))
    monkeypatch.setattr(programs, "get_tool_path_config_value", lambda name, key, platform = None: "/tools/%s/%s/%s" % (name, key, platform))
    monkeypatch.setattr(programs, "get_emulator_path_config_value", lambda name, key, platform = None: "/emulators/%s/%s/%s" % (name, key, platform))
    monkeypatch.setattr(programsetup.platform_info, "get_current_platform", lambda: "linux")
    monkeypatch.setattr(programsetup.logger, "log_error", state["errors"].append)

    for module, function_name in programsetup.STEP_KINDS.values():
        def record(function_name = function_name, **kwargs):
            state["calls"].append((function_name, kwargs))
            return state["results"].get(function_name, True)
        monkeypatch.setattr(module, function_name, record)
    return state


def run(state, steps, family = programcatalog.FAMILY_TOOLS, name = "Tool", offline = False):
    state["steps"] = steps
    return programsetup.run_setup_steps(family, name, offline = offline, setup_params = PARAMS)


FLAGS = {"verbose": True, "pretend_run": False, "exit_on_failure": False}


@pytest.mark.parametrize("kind, function_name", [
    ("webpage_release", "download_webpage_release"),
    ("github_release", "download_github_release"),
    ("general_release", "download_general_release"),
    ("appimage_build", "build_appimage_from_source"),
    ("binary_build", "build_binary_from_source"),
])
def test_a_release_step_installs_into_the_program_dirs_with_a_backup(setup_world, kind, function_name):
    setup_world["needs_install"] = {("Tool", "linux")}

    assert run(setup_world, [{"kind": kind, "platform": "linux", "ends_with": ".zip"}]) is True
    assert setup_world["calls"] == [(function_name, {
        "ends_with": ".zip", "install_name": "Tool", "install_dir": "/tools/Tool/linux",
        "backups_dir": "/backups/Tool/linux", "locker_type": "LOCKER", "skip_autobackup": True, **FLAGS})]


def test_a_stored_release_installs_from_the_backups_dir(setup_world):
    setup_world["needs_install"] = {("Tool", "windows")}

    run(setup_world, [{"kind": "stored_release", "platform": "windows", "search_file": "Tool.exe"}], offline = True)

    assert setup_world["asked"] == (programcatalog.FAMILY_TOOLS, "Tool", True)
    assert setup_world["calls"] == [("setup_stored_release", {
        "search_file": "Tool.exe", "install_name": "Tool", "install_dir": "/tools/Tool/windows",
        "archive_dir": "/backups/Tool/windows", **FLAGS})]


def test_a_library_clones_and_archives_once_its_dir_needs_filling(setup_world):
    # The gate is asked once for the group: the clone fills the dir the archive step would see.
    setup_world["needs_install"] = {("Tool", "library")}
    steps = [
        {"kind": "github_repository", "platform": "lib", "for": "library", "github_branch": "{program_config:github_branch}"},
        {"kind": "github_archive", "platform": "lib", "for": "library"},
    ]

    assert run(setup_world, steps) is True
    assert setup_world["gates"] == [("library", "Tool", "lib")]
    assert setup_world["calls"] == [
        ("download_github_repository", {"github_branch": "tool:Tool:github_branch", "output_dir": "/libs/Tool/lib", **FLAGS}),
        ("archive_github_repository", {"output_dir": "/libbackups/Tool/lib", "locker_type": "LOCKER", **FLAGS}),
    ]


@pytest.mark.parametrize("kind, function_name", [
    ("tool_requirements", "setup_tool_requirements"),
    ("tool_requirements_offline", "setup_tool_requirements_offline"),
])
def test_requirements_are_installed_by_the_tools_name(setup_world, kind, function_name):
    setup_world["needs_install"] = {("Tool", "library")}

    run(setup_world, [{"kind": kind, "platform": "lib", "for": "library"}])

    assert setup_world["calls"] == [(function_name, {"tool_name": "Tool", **FLAGS})]


def test_an_emulators_config_values_come_from_the_emulator_config(setup_world):
    setup_world["needs_install"] = {("Emu", "linux")}

    run(setup_world, [{"kind": "github_release", "platform": "linux", "starts_with": "{program_config:prefix}"}],
        family = programcatalog.FAMILY_EMULATORS, name = "Emu")

    assert setup_world["calls"][0][1]["starts_with"] == "emulator:Emu:prefix"



@pytest.mark.parametrize("family, name, expected", [
    (programcatalog.FAMILY_TOOLS, "Tool", "/tools/Tool/themes_dir/windows"),
    (programcatalog.FAMILY_EMULATORS, "Emu", "/emulators/Emu/themes_dir/windows"),
])
def test_a_path_config_value_is_the_programs_path_for_the_steps_platform(setup_world, family, name, expected):
    setup_world["needs_install"] = {(name, "windows")}

    run(setup_world, [{"kind": "github_release", "platform": "windows", "install_dir": "{program_path_config:themes_dir}"}],
        family = family, name = name)

    assert setup_world["calls"][0][1]["install_dir"] == expected


def test_a_path_config_value_may_name_a_sub_path(setup_world):
    setup_world["needs_install"] = {("Tool", "linux")}

    run(setup_world, [{"kind": "github_repository", "platform": "linux", "output_dir": "{program_path_config:themes_dir}/Grid"}])

    assert setup_world["calls"][0][1]["output_dir"] == "/tools/Tool/themes_dir/linux/Grid"


def test_a_step_for_another_host_is_left_out(setup_world):
    setup_world["needs_install"] = {("Tool", "library")}
    steps = [
        {"kind": "binary_build", "platform": "lib", "for": "library", "host": "windows", "build_cmd": ["gradlew.bat"]},
        {"kind": "binary_build", "platform": "lib", "for": "library", "host": "linux", "build_cmd": ["./gradlew"]},
    ]

    assert run(setup_world, steps) is True
    assert [call[1]["build_cmd"] for call in setup_world["calls"]] == [["./gradlew"]]
    assert "host" not in setup_world["calls"][0][1]


def test_a_failed_step_is_named_by_its_label(setup_world):
    setup_world["needs_install"] = {("Tool", "linux")}
    setup_world["results"]["download_github_repository"] = False

    assert run(setup_world, [{"kind": "github_repository", "platform": "linux", "label": "Tool theme"}]) is False
    assert setup_world["errors"] == ["Could not setup Tool theme"]
    assert "label" not in setup_world["calls"][0][1]

def test_a_release_type_is_given_by_its_member_name(setup_world):
    setup_world["needs_install"] = {("Tool", "linux")}

    run(setup_world, [{"kind": "github_release", "platform": "linux", "release_type": "ARCHIVE"}])

    assert setup_world["calls"][0][1]["release_type"] is config.ReleaseType.ARCHIVE


def test_a_step_may_install_another_program_the_data_ships(setup_world):
    setup_world["needs_install"] = {("Chdman", "linux")}

    run(setup_world, [{"kind": "github_release", "program": "Chdman", "platform": "linux"}])

    assert setup_world["gates"] == [("program", "Chdman", "linux")]
    assert setup_world["calls"][0][1]["install_dir"] == "/tools/Chdman/linux"
    assert setup_world["calls"][0][1]["install_name"] == "Chdman"


def test_a_step_keeps_an_argument_it_gives_itself(setup_world):
    setup_world["needs_install"] = {("Tool", "linux")}

    run(setup_world, [{"kind": "github_release", "platform": "linux", "install_name": "Other"}])

    assert setup_world["calls"][0][1]["install_name"] == "Other"


def test_an_installed_platform_is_skipped(setup_world):
    setup_world["needs_install"] = {("Tool", "linux")}
    steps = [{"kind": "github_release", "platform": "windows"}, {"kind": "github_release", "platform": "linux"}]

    assert run(setup_world, steps) is True
    assert [call[1]["install_dir"] for call in setup_world["calls"]] == ["/tools/Tool/linux"]


def test_a_failed_step_stops_the_setup_and_names_the_program(setup_world):
    setup_world["needs_install"] = {("Chdman", "windows"), ("Tool", "linux")}
    setup_world["results"]["download_github_release"] = False
    steps = [
        {"kind": "github_release", "program": "Chdman", "platform": "windows"},
        {"kind": "general_release", "platform": "linux"},
    ]

    assert run(setup_world, steps) is False
    assert [call[0] for call in setup_world["calls"]] == ["download_github_release"]
    assert setup_world["errors"] == ["Could not setup Chdman"]


def test_a_program_without_steps_has_nothing_to_set_up(setup_world):
    assert run(setup_world, []) is True
    assert setup_world["calls"] == []


def test_default_run_flags_are_used_without_setup_params(setup_world):
    setup_world["steps"] = [{"kind": "github_release", "platform": "linux"}]
    setup_world["needs_install"] = {("Tool", "linux")}

    assert programsetup.run_setup_steps(programcatalog.FAMILY_TOOLS, "Tool") is True
    assert setup_world["calls"][0][1]["pretend_run"] is False


def test_an_unknown_step_kind_is_refused(setup_world):
    setup_world["needs_install"] = {("Tool", "linux")}

    with pytest.raises(ValueError, match = "teleport"):
        run(setup_world, [{"kind": "teleport", "platform": "linux"}])


@pytest.mark.parametrize("family, name", [
    (family, name) for family in (programcatalog.FAMILY_TOOLS, programcatalog.FAMILY_EMULATORS)
    for name in programcatalog.load_family(family)])
def test_every_program_files_steps_of_known_kinds(family, name):
    steps = programcatalog.get_setup_steps(family, name) + programcatalog.get_setup_steps(family, name, offline = True)

    assert [step["kind"] for step in steps if step["kind"] not in programsetup.STEP_KINDS] == []
