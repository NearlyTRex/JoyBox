# Imports
import json
import os

# Third-party imports
import pytest

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
        "/tools/Sunshine/windows/config/apps.json",
        "/tools/Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/apps.json",
    ]


def test_configure_leaves_the_web_page_settings_alone(steps):
    # An empty sunshine.conf is only touched, so settings saved in Sunshine's
    # web page survive another setup.
    assert sunshine.Sunshine().configure()

    confs = [kwargs for kwargs in steps.made("touch_file") if kwargs["src"].endswith("sunshine.conf")]
    assert [kwargs["contents"] for kwargs in confs] == ["", ""]


###########################################################
# Apps
###########################################################

def app_names(platform):
    return [app["name"] for app in json.loads(sunshine.build_apps(platform))["apps"]]


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_clients_can_start_the_desktop_pegasus_and_steam(platform):
    assert app_names(platform) == ["Desktop", "Pegasus", "Steam Big Picture"]


def test_pegasus_starts_through_the_joybox_command(isolated_settings):
    apps = json.loads(sunshine.build_apps("linux"))["apps"]

    assert apps[1]["cmd"].endswith(os.path.join("bin", "launch_pegasus"))


def test_linux_apps_get_the_real_home_back():
    # The AppImage's portable home would otherwise hide JoyBox.ini and Steam.
    assert json.loads(sunshine.build_apps("linux"))["env"] == {"HOME": os.path.expanduser("~")}
    assert json.loads(sunshine.build_apps("windows"))["env"] == {}


def test_steam_is_detached_and_closed_when_the_stream_ends():
    steam = json.loads(sunshine.build_apps("linux"))["apps"][2]

    assert steam["detached"] == ["setsid steam steam://open/bigpicture"]
    assert steam["prep-cmd"] == [{"do": "", "undo": "setsid steam steam://close/bigpicture"}]


###########################################################
# App menu launcher
###########################################################

@pytest.mark.parametrize("streaming_host", [True, False])
def test_configure_puts_sunshine_in_the_menu_only_on_a_streaming_host(steps, isolated_settings, streaming_host):
    isolated_settings.set_value("Tools.Sunshine", "sunshine_streaming_host", str(streaming_host))

    assert sunshine.Sunshine().configure()

    launcher = steps.made("set_launcher")[0]
    assert launcher["enabled"] is streaming_host
    assert (launcher["filename"], launcher["command"]) == ("joybox-sunshine.desktop", "launch_sunshine")


def test_a_failed_launcher_fails_the_configure(steps):
    steps.fail_at = len(sunshine.config_files)

    assert not sunshine.Sunshine().configure()
    assert steps.errors == ["Could not setup the Sunshine launcher"]
