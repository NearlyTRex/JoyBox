# Local imports
from joybox.tools import mametools
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert mametools.MameTools().setup()

    assert steps.names() == [
        "download_github_release",
        "build_appimage_from_source",
    ]
    assert installed_to(steps) == [
        "/install/MameChdman/windows",
        "/install/MameChdman/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, mametools.MameTools())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, mametools.MameTools())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, mametools.MameTools())


def test_setup_offline_matches_the_online_install(steps):
    # The windows release is a self-extracting archive, not the program
    assert_offline_matches_online(steps, mametools.MameTools())
