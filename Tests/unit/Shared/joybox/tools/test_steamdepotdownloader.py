# Local imports
from joybox.tools import steamdepotdownloader
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert steamdepotdownloader.SteamDepotDownloader().setup()

    assert steps.names() == [
        "download_github_release",
        "download_github_release",
    ]
    assert installed_to(steps) == [
        "/install/SteamDepotDownloader/windows",
        "/install/SteamDepotDownloader/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, steamdepotdownloader.SteamDepotDownloader())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, steamdepotdownloader.SteamDepotDownloader())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, steamdepotdownloader.SteamDepotDownloader())


def test_setup_offline_matches_the_online_install(steps):
    # A stored archive must come out executable, like a fresh download
    assert_offline_matches_online(steps, steamdepotdownloader.SteamDepotDownloader())
