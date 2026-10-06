# Local imports
from joybox.tools import itchdl
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_library(steps):
    assert itchdl.ItchDL().setup()

    assert steps.names() == [
        "download_github_repository",
        "archive_github_repository",
    ]
    assert installed_to(steps) == ["/install/ItchDL/lib"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, itchdl.ItchDL())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, itchdl.ItchDL())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, itchdl.ItchDL())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, itchdl.ItchDL())
