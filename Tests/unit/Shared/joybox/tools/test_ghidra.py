# Imports
import os

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
    assert sorted(written) == sorted("/tools/" + path for path in ghidra.config_files)
    for dest_path, src_filename in ghidra.config_files.items():
        with open(os.path.join(ghidra.extra_files_dir, src_filename)) as handle:
            assert written["/tools/" + dest_path] == handle.read().strip()


def test_configure_stops_when_a_language_file_is_missing(steps, monkeypatch):
    monkeypatch.setattr(ghidra, "extra_files_dir", "/nonexistent")

    assert ghidra.Ghidra().configure() is False
    assert steps.calls == []
    assert steps.errors
