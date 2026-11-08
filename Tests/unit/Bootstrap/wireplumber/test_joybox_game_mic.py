# Imports
import os

# Local imports
import joybox.bootstrap as bootstrap


###########################################################
# Game mic pinning
#
# The WirePlumber script runs against a fake host. Recording streams of Wine
# and Proton games are pinned to the silent mic through the default metadata's
# target.object, and pinned again whenever anything retargets them; allowed
# games, protected apps and every other stream are left alone.
###########################################################

SCRIPT = os.path.join(bootstrap.get_data_dir(), "wireplumber", "joybox-game-mic.lua")
MIC_SERIAL = "57"
CONFIG = {"mic.node-name": "joybox_game_mic", "allow": "Allowed.exe", "protect": "Discord, OBS"}


def start(wireplumber, config = None):
    wireplumber.run(SCRIPT, CONFIG if config is None else config)
    metadata = wireplumber.metadata()
    wireplumber.node(**{"node.name": "joybox_game_mic", "object.serial": MIC_SERIAL})
    return metadata


def stream(wireplumber, binary, name):
    return wireplumber.node(**{
        "media.class": "Stream/Input/Audio",
        "application.process.binary": binary,
        "application.name": name})


def target(wireplumber, metadata, node):
    return wireplumber.find(metadata, node["bound-id"], "target.object")


def test_a_wine_game_is_pinned_to_the_silent_mic(wireplumber):
    metadata = start(wireplumber)

    game = stream(wireplumber, "wine64-preloader", "Game")

    assert target(wireplumber, metadata, game) == MIC_SERIAL
    assert list(wireplumber.host.logged.values()) == ["pinning Game to joybox_game_mic"]


def test_an_exe_named_app_is_a_game_whatever_its_binary(wireplumber):
    metadata = start(wireplumber)

    assert target(wireplumber, metadata, stream(wireplumber, "proton", "Lethal Company.EXE")) == MIC_SERIAL


def test_other_streams_keep_their_mic(wireplumber):
    metadata = start(wireplumber)

    assert target(wireplumber, metadata, stream(wireplumber, "firefox", "Firefox")) is None


def test_allowed_games_and_protected_apps_are_left_alone(wireplumber):
    metadata = start(wireplumber)

    assert target(wireplumber, metadata, stream(wireplumber, "wine64", "allowed.exe")) is None
    assert target(wireplumber, metadata, stream(wireplumber, "Discord", "Voice.exe")) is None
    assert target(wireplumber, metadata, stream(wireplumber, "wine", "obs")) is None


def test_a_game_retargeted_elsewhere_is_pinned_again(wireplumber):
    metadata = start(wireplumber)
    game = stream(wireplumber, "wine64", "Game.exe")

    wireplumber.set(metadata, game["bound-id"], "target.object", "99")
    assert target(wireplumber, metadata, game) == MIC_SERIAL

    wireplumber.set(metadata, game["bound-id"], "target.node", "99")
    assert target(wireplumber, metadata, game) == MIC_SERIAL


def test_unrelated_metadata_changes_are_ignored(wireplumber):
    metadata = start(wireplumber)
    game = stream(wireplumber, "wine64", "Game.exe")

    wireplumber.set(metadata, game["bound-id"], "target.object", "99")
    wireplumber.set(metadata, game["bound-id"], "volume", "1")
    wireplumber.set(metadata, 1, "target.object", "99")

    assert target(wireplumber, metadata, game) == MIC_SERIAL
    assert wireplumber.find(metadata, 1, "target.object") == "99"


def test_games_that_start_before_the_mic_are_pinned_when_it_appears(wireplumber):
    wireplumber.run(SCRIPT, CONFIG)
    metadata = wireplumber.metadata()
    game = stream(wireplumber, "wine64", "Game.exe")
    assert target(wireplumber, metadata, game) is None

    wireplumber.node(**{"node.name": "joybox_game_mic", "object.serial": MIC_SERIAL})

    assert target(wireplumber, metadata, game) == MIC_SERIAL


def test_games_that_start_before_the_metadata_are_pinned_when_it_appears(wireplumber):
    wireplumber.run(SCRIPT, CONFIG)
    wireplumber.node(**{"node.name": "joybox_game_mic", "object.serial": MIC_SERIAL})
    game = stream(wireplumber, "wine64", "Game.exe")

    metadata = wireplumber.metadata()

    assert target(wireplumber, metadata, game) == MIC_SERIAL


def test_without_config_the_default_mic_name_is_used(wireplumber):
    wireplumber.run(SCRIPT)
    metadata = wireplumber.metadata()
    wireplumber.node(**{"node.name": "joybox_game_mic", "object.serial": MIC_SERIAL})

    assert target(wireplumber, metadata, stream(wireplumber, "wine64", "Allowed.exe")) == MIC_SERIAL


def test_a_stream_without_app_properties_is_not_a_game(wireplumber):
    metadata = start(wireplumber)

    assert target(wireplumber, metadata, wireplumber.node(**{"media.class": "Stream/Input/Audio"})) is None
