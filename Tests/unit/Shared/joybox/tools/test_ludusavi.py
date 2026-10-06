# Local imports
from joybox.tools import ludusavi
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_both_platforms(steps):
    assert ludusavi.Ludusavi().setup()

    assert steps.names() == [
        "download_github_release",
        "download_github_release",
    ]
    assert installed_to(steps) == [
        "/install/Ludusavi/windows",
        "/install/Ludusavi/linux",
    ]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, ludusavi.Ludusavi())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, ludusavi.Ludusavi())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, ludusavi.Ludusavi())


def test_setup_offline_matches_the_online_install(steps):
    # A stored archive must come out executable, like a fresh download
    assert_offline_matches_online(steps, ludusavi.Ludusavi())


def test_configure_makes_each_install_portable(steps):
    assert ludusavi.Ludusavi().configure()

    written = {kwargs["src"]: kwargs["contents"] for kwargs in steps.made("touch_file")}
    assert written["/tools/Ludusavi/windows/ludusavi.portable"] == ""
    assert written["/tools/Ludusavi/linux/ludusavi.portable"] == ""
    # Each platform's backups use its own path separator
    assert "path: .\\ludusavi-backup" in written["/tools/Ludusavi/windows/config.yaml"]
    assert "path: ./ludusavi-backup" in written["/tools/Ludusavi/linux/config.yaml"]
