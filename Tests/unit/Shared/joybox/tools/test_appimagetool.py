# Local imports
from joybox.tools import appimagetool
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_linux_program(steps):
    assert appimagetool.AppImageTool().setup()

    assert steps.names() == ["download_github_release"]
    assert installed_to(steps) == ["/install/AppImageTool/linux"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, appimagetool.AppImageTool())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, appimagetool.AppImageTool())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, appimagetool.AppImageTool())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, appimagetool.AppImageTool())


def test_configure_lays_out_the_appimage_skeleton(steps):
    assert appimagetool.AppImageTool().configure()

    assert steps.made("copy_file_or_directory")[0]["dest"] == "/install/AppImageTool/linux/icon.svg"
    assert [kwargs["src"] for kwargs in steps.made("touch_file")] == ["/tools/AppImageTool/linux/app.desktop"]
    assert steps.made("touch_file")[0]["contents"].startswith("[Desktop Entry]")


def test_configure_does_nothing_off_linux(steps):
    steps.platform = "windows"

    assert appimagetool.AppImageTool().configure()
    assert steps.calls == []
