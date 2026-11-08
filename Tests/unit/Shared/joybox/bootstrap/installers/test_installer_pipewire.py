# Imports
import os

# Local imports
import joybox.bootstrap as bootstrap
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# PipeWire
#
# The silent mic ships only in silent mode, the volume lock unless the game
# mic is off; protected apps are carved out of the lock, and outputs join it
# when asked.
###########################################################

PULSE_FILE = "99-joybox-game-mic-pulse.conf"


def make():
    return installers.Pipewire(RecordingConnection())


def set_game_mic(settings, **values):
    for field, value in values.items():
        settings.set_value("UserData.GameMic", "game_mic_" + field, value)


def test_only_local_ubuntu_is_supported(isolated_settings):
    assert make().get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_every_drop_in_ships_in_the_bootstrap_folder(isolated_settings):
    pipewire = make()

    shipped = [name for name, _, _ in pipewire.files
               if os.path.isfile(os.path.join(bootstrap.get_data_dir(), "pipewire", name))]
    assert shipped == [name for name, _, _ in pipewire.files]
    assert shipped


def test_the_drop_ins_go_where_pipewire_reads_them(isolated_settings):
    assert make().get_destinations() == [
        os.path.expanduser("~/.config/pipewire/pipewire.conf.d/99-joybox-game-mic.conf"),
        os.path.expanduser("~/.config/pipewire/pipewire-pulse.conf.d/99-joybox-game-mic.conf")]


def test_no_pipewire_service_restarts_without_the_user(isolated_settings):
    assert make().safe_services == ()


def test_the_silent_mic_is_the_node_the_wireplumber_script_pins_to(isolated_settings):
    pipewire = make()
    wireplumber = installers.Wireplumber(RecordingConnection())

    assert 'node.name        = "joybox_game_mic"' in pipewire.get_rendered_contents("99-joybox-game-mic.conf")
    assert '"mic.node-name"] = "joybox_game_mic"' in wireplumber.get_rendered_contents("99-joybox-game-mic.lua")


def test_each_mode_deploys_its_files(isolated_settings):
    pipewire = make()

    set_game_mic(isolated_settings, mode = "silent")
    assert pipewire.get_active_files() == ["99-joybox-game-mic.conf", PULSE_FILE]
    set_game_mic(isolated_settings, mode = "locked")
    assert pipewire.get_active_files() == [PULSE_FILE]
    set_game_mic(isolated_settings, mode = "off")
    assert pipewire.get_active_files() == []


def test_games_may_not_change_mic_volume(isolated_settings):
    set_game_mic(isolated_settings, protect = "")
    contents = make().get_rendered_contents(PULSE_FILE)

    assert '{ application.process.binary = "~.*wine.*" }' in contents
    assert "quirks = [ block-source-volume ]" in contents


def test_protected_apps_are_left_out_of_every_match(isolated_settings):
    set_game_mic(isolated_settings, protect = "Discord, obs.bin")
    contents = make().get_rendered_contents(PULSE_FILE)

    negation = '"!~^([dD][iI][sS][cC][oO][rR][dD]|[oO][bB][sS]\\\\.[bB][iI][nN])$"'
    assert contents.count("application.process.binary = " + negation) == 2
    assert contents.count("application.name = " + negation) == 2


def test_locking_outputs_also_blocks_sink_volume(isolated_settings):
    set_game_mic(isolated_settings, lock_output = "True")

    assert "quirks = [ block-source-volume block-sink-volume ]" in make().get_rendered_contents(PULSE_FILE)
