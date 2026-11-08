# Imports
import os

# Local imports
import joybox.bootstrap as bootstrap
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# WirePlumber
#
# Pinning runs only in silent mode, and the policy config hands the allowed
# games and protected apps to the script.
###########################################################

POLICY_FILE = "99-joybox-game-mic.lua"


def make():
    return installers.Wireplumber(RecordingConnection())


def test_only_local_ubuntu_is_supported(isolated_settings):
    assert make().get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_every_file_ships_in_the_bootstrap_folder(isolated_settings):
    wireplumber = make()

    shipped = [name for name, _, _ in wireplumber.files
               if os.path.isfile(os.path.join(bootstrap.get_data_dir(), "wireplumber", name))]
    assert shipped == [name for name, _, _ in wireplumber.files]
    assert shipped


def test_the_policy_config_and_script_go_where_wireplumber_finds_them(isolated_settings):
    assert make().get_destinations() == [
        os.path.expanduser("~/.config/wireplumber/policy.lua.d/99-joybox-game-mic.lua"),
        os.path.expanduser("~/.config/wireplumber/scripts/joybox-game-mic.lua")]


def test_wireplumber_restarts_on_its_own(isolated_settings):
    assert make().safe_services == ("wireplumber",)


def test_pinning_runs_only_in_silent_mode(isolated_settings):
    wireplumber = make()

    isolated_settings.set_value("UserData.GameMic", "game_mic_mode", "silent")
    assert wireplumber.get_active_files() == [POLICY_FILE, "joybox-game-mic.lua"]
    isolated_settings.set_value("UserData.GameMic", "game_mic_mode", "locked")
    assert wireplumber.get_active_files() == []


def test_the_policy_config_passes_the_app_lists_to_the_script(isolated_settings):
    isolated_settings.set_value("UserData.GameMic", "game_mic_allow", "Lethal Company.exe, DRG.exe")
    isolated_settings.set_value("UserData.GameMic", "game_mic_protect", "Discord")
    contents = make().get_rendered_contents(POLICY_FILE)

    assert 'load_script("joybox-game-mic.lua"' in contents
    assert '["allow"] = "Lethal Company.exe,DRG.exe",' in contents
    assert '["protect"] = "Discord",' in contents


def test_the_script_ships_unrendered(isolated_settings):
    wireplumber = make()

    assert wireplumber.get_rendered_contents("joybox-game-mic.lua") == wireplumber.get_contents("joybox-game-mic.lua")
