# Local imports
from joybox.tools import xorriso
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert xorriso.XorrISO().setup()

    assert steps.names() == [
        "download_github_repository",
        "archive_github_repository",
        "build_appimage_from_source",
    ]
    assert installed_to(steps) == [
        "/install/XorrISO/windows",
        "/install/XorrISO/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, xorriso.XorrISO())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, xorriso.XorrISO())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, xorriso.XorrISO())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, xorriso.XorrISO())
