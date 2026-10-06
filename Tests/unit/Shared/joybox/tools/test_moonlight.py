# Local imports
from joybox.tools import moonlight
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert moonlight.Moonlight().setup()

    assert steps.names() == [
        "download_github_release",
        "download_github_release",
    ]
    assert installed_to(steps) == [
        "/install/Moonlight/windows",
        "/install/Moonlight/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, moonlight.Moonlight())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, moonlight.Moonlight())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, moonlight.Moonlight())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, moonlight.Moonlight())


def test_configure_writes_into_the_appimage_home(steps):
    assert moonlight.Moonlight().configure()

    assert [kwargs["src"] for kwargs in steps.made("touch_file")] == [
        "/tools/Moonlight/linux/Moonlight.AppImage.home/.config/Moonlight Game Streaming Project/Moonlight.conf"]
