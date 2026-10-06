# Local imports
from joybox.tools import psvstrip
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_windows_program(steps):
    assert psvstrip.PSVStrip().setup()

    assert steps.names() == ["download_github_release"]
    assert installed_to(steps) == ["/install/PSVStrip/windows"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, psvstrip.PSVStrip())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, psvstrip.PSVStrip())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, psvstrip.PSVStrip())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, psvstrip.PSVStrip())
