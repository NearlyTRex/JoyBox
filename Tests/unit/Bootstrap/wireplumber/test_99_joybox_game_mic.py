# Imports
import os

# Local imports
import joybox.bootstrap as bootstrap
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Game mic policy file
#
# WirePlumber runs the policy file, which loads the pinning script with the
# mic's node name and the app lists the installer fills in.
###########################################################

POLICY = os.path.join(bootstrap.get_data_dir(), "wireplumber", "99-joybox-game-mic.lua")


def loaded(wireplumber, path):
    wireplumber.run(path)
    return [(entry["name"], dict(entry["args"])) for entry in wireplumber.host.loaded.values()]


def test_the_shipped_template_loads_the_pinning_script(wireplumber):
    assert loaded(wireplumber, POLICY) == [("joybox-game-mic.lua", {
        "mic.node-name": "joybox_game_mic", "allow": "${allow}", "protect": "${protect}"})]


def test_the_rendered_policy_hands_over_the_app_lists(wireplumber, isolated_settings, tmp_path):
    isolated_settings.set_value("UserData.GameMic", "game_mic_allow", 'Say "Hi".exe, C:\\Game.exe')
    isolated_settings.set_value("UserData.GameMic", "game_mic_protect", "Discord")
    rendered = tmp_path / "policy.lua"
    rendered.write_text(installers.Wireplumber(RecordingConnection()).get_rendered_contents("99-joybox-game-mic.lua"))

    assert loaded(wireplumber, rendered) == [("joybox-game-mic.lua", {
        "mic.node-name": "joybox_game_mic", "allow": 'Say "Hi".exe,C:\\Game.exe', "protect": "Discord"})]
