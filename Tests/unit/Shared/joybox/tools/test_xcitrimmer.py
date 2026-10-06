# Local imports
from joybox.tools import xcitrimmer
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_library(steps):
    assert xcitrimmer.XCITrimmer().setup()

    assert steps.names() == [
        "download_github_repository",
        "setup_tool_requirements",
        "archive_github_repository",
    ]
    assert installed_to(steps) == ["/install/XCITrimmer/lib"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, xcitrimmer.XCITrimmer())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, xcitrimmer.XCITrimmer())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, xcitrimmer.XCITrimmer())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, xcitrimmer.XCITrimmer())
