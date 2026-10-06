# Local imports
from joybox.tools import balenaetcher
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert balenaetcher.BalenaEtcher().setup()

    assert steps.names() == [
        "download_github_release",
        "download_github_release",
    ]
    assert installed_to(steps) == [
        "/install/BalenaEtcher/windows",
        "/install/BalenaEtcher/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, balenaetcher.BalenaEtcher())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, balenaetcher.BalenaEtcher())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, balenaetcher.BalenaEtcher())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, balenaetcher.BalenaEtcher())
