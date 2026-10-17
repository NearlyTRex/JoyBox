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


###########################################################
# Web page login
#
# Written so Sunshine's web page never asks for one. Sunshine keeps a hash of
# the password beside the clients paired with it, so the rest of its state
# must survive.
###########################################################

# What Sunshine's own --creds wrote for VECTOR_PHRASE with this salt
VECTOR_PHRASE = "test-vector-password"
VECTOR_SALT = "EEoiXffZonxUyWRp"
VECTOR_HASH = "D24BFF99EB0DC8ECB5CCF0AF1A22A4D2A6903368D0BA2915C53E7B8D865D265D"
LOGIN_PHRASE = "joybox-login-value"


def test_a_password_is_hashed_as_sunshine_checks_it():
    assert sunshine.hash_password(VECTOR_PHRASE, VECTOR_SALT) == VECTOR_HASH


def read_state(path):
    with open(path, encoding = "utf-8") as handle:
        return json.load(handle)


def test_a_login_is_written_with_a_fresh_salt(tmp_path):
    state_file = str(tmp_path / "sunshine_state.json")

    assert sunshine.write_login(state_file, "player", LOGIN_PHRASE)

    state = read_state(state_file)
    assert state["username"] == "player" and len(state["salt"]) == sunshine.salt_length
    assert state["password"] == sunshine.hash_password(LOGIN_PHRASE, state["salt"])
    assert oct(os.stat(state_file).st_mode & 0o777) == "0o600"


def test_the_rest_of_the_state_is_kept(tmp_path):
    state_file = tmp_path / "sunshine_state.json"
    state_file.write_text(json.dumps({"username": "old", "salt": "x", "password": "y", "root": {"named_devices": ["tv"]}}))

    assert sunshine.write_login(str(state_file), "player", LOGIN_PHRASE)

    assert read_state(state_file)["root"] == {"named_devices": ["tv"]}


def test_a_current_login_is_not_written_again(tmp_path):
    # Rewriting would change the salt for nothing on every configure
    state_file = tmp_path / "sunshine_state.json"
    original = {"username": "player", "salt": VECTOR_SALT, "password": VECTOR_HASH}
    state_file.write_text(json.dumps(original))

    assert sunshine.write_login(str(state_file), "player", VECTOR_PHRASE)

    assert read_state(state_file) == original


@pytest.mark.parametrize("contents", ["not json", "[1, 2]"])
def test_an_unreadable_state_is_left_alone(tmp_path, contents):
    # Writing over it would lose the paired clients it may hold
    state_file = tmp_path / "sunshine_state.json"
    state_file.write_text(contents)

    assert not sunshine.write_login(str(state_file), "player", LOGIN_PHRASE)

    assert state_file.read_text() == contents


def test_configure_writes_the_login_for_each_platform(steps, isolated_settings):
    isolated_settings.set_value("UserData.Streaming", "sunshine_user", "player")
    isolated_settings.set_value("UserData.Streaming", "sunshine_pass", LOGIN_PHRASE)

    assert sunshine.Sunshine().configure()

    logins = [kwargs for kwargs in steps.made("touch_file") if kwargs["src"].endswith("sunshine_state.json")]
    assert [kwargs["src"] for kwargs in logins] == [
        "/tools/Sunshine/windows/config/sunshine_state.json",
        "/tools/Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine_state.json",
    ]
    assert all(kwargs["private"] for kwargs in logins)


def test_configure_without_a_login_leaves_the_web_page_to_ask(steps, isolated_settings):
    isolated_settings.set_value("UserData.Streaming", "sunshine_user", "")

    assert sunshine.Sunshine().configure()

    assert not any(kwargs["src"].endswith("sunshine_state.json") for kwargs in steps.made("touch_file"))


def test_a_failed_login_fails_the_configure(steps, isolated_settings):
    isolated_settings.set_value("UserData.Streaming", "sunshine_user", "player")
    isolated_settings.set_value("UserData.Streaming", "sunshine_pass", LOGIN_PHRASE)
    steps.fail_at = len(sunshine.config_files)

    assert not sunshine.Sunshine().configure()
    assert steps.errors == ["Could not setup the Sunshine login"]
