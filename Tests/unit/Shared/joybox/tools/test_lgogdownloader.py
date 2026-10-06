# Local imports
from joybox.tools import lgogdownloader
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_linux_program(steps):
    assert lgogdownloader.LGOGDownloader().setup()

    assert steps.names() == ["build_appimage_from_source"]
    assert installed_to(steps) == ["/install/LGOGDownloader/linux"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, lgogdownloader.LGOGDownloader())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, lgogdownloader.LGOGDownloader())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, lgogdownloader.LGOGDownloader())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, lgogdownloader.LGOGDownloader())


def test_configure_creates_an_empty_config(steps):
    assert lgogdownloader.LGOGDownloader().configure()

    assert [(kwargs["src"], kwargs["contents"]) for kwargs in steps.made("touch_file")] == [
        ("/tools/LGOGDownloader/linux/LGOGDownloader.AppImage.home/.config/lgogdownloader/config.cfg", "")]


def test_configure_does_nothing_off_linux(steps):
    steps.platform = "windows"

    assert lgogdownloader.LGOGDownloader().configure()
    assert steps.calls == []
