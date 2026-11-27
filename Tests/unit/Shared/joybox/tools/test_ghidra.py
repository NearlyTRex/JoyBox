# Local imports
from joybox.tools import ghidra
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_library(steps):
    assert ghidra.Ghidra().setup()

    assert steps.names() == ["build_binary_from_source"]
    assert installed_to(steps) == ["/install/Ghidra/lib"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, ghidra.Ghidra())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, ghidra.Ghidra())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, ghidra.Ghidra())


def test_setup_offline_matches_the_online_install(steps):
    # The built zip nests ghidraRun under a versioned folder
    assert_offline_matches_online(steps, ghidra.Ghidra())


def test_setup_builds_with_the_platform_gradle_wrapper(steps):
    assert ghidra.Ghidra().setup()
    assert steps.made("build_binary_from_source")[0]["build_cmd"][0] == "./gradlew"

    steps.platform = "windows"
    steps.reset()
    assert ghidra.Ghidra().setup()
    assert steps.made("build_binary_from_source")[0]["build_cmd"][0] == "gradlew.bat"


def test_configure_installs_the_watcom_language_files(steps):
    assert ghidra.Ghidra().configure()

    written = {kwargs["src"]: kwargs["contents"] for kwargs in steps.made("touch_file")}
    expected = ghidra.Ghidra().get_config_files()
    assert sorted(written) == sorted("/tools/" + path for path in expected)
    assert all(written["/tools/" + path] == contents.strip() for path, contents in expected.items())
