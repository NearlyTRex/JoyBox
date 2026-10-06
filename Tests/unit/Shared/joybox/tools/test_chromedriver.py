# Local imports
from joybox.tools import chromedriver
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert chromedriver.ChromeDriver().setup()

    assert steps.names() == [
        "download_webpage_release",
        "download_webpage_release",
    ]
    assert installed_to(steps) == [
        "/install/ChromeDriver/windows",
        "/install/ChromeDriver/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, chromedriver.ChromeDriver())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, chromedriver.ChromeDriver())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, chromedriver.ChromeDriver())


def test_setup_offline_matches_the_online_install(steps):
    # The driver zip nests the binary under a platform folder
    assert_offline_matches_online(steps, chromedriver.ChromeDriver())
