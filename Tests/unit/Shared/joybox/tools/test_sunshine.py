# Local imports
from joybox.tools import sunshine
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert sunshine.Sunshine().setup()

    assert steps.names() == [
        "download_github_release",
        "download_github_release",
    ]
    assert installed_to(steps) == [
        "/install/Sunshine/windows",
        "/install/Sunshine/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, sunshine.Sunshine())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, sunshine.Sunshine())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, sunshine.Sunshine())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, sunshine.Sunshine())


def test_configure_writes_a_config_for_each_platform(steps):
    assert sunshine.Sunshine().configure()

    assert [kwargs["src"] for kwargs in steps.made("touch_file")] == [
        "/tools/Sunshine/windows/config/sunshine.conf",
        "/tools/Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine.conf",
    ]
