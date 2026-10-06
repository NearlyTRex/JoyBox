# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import yuzu
from emulator_helpers import (
    make_packages, BAD_MD5, PLATFORMS, SETUP_METHODS, Seams, all_params, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_writes_every_config_file, expected_stored, launch_cmd, stored_releases)


###########################################################
# Yuzu
#
# A Switch program restored only from stored early-access builds, skipped when
# missing; configure writes a profiles file for the configured Switch user,
# and add-ons are NSPs installed into the emulated NAND.
###########################################################

PROFILE_USER_ID = "0123456789ABCDEF0123456789ABCDEF"
PROFILE_ACCOUNT = "player"
DEFAULT_USER_ID = "F6F389D41D6BC0BDD6BD928C526AE556"


@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, yuzu)


@pytest.fixture
def profile(isolated_settings):
    isolated_settings.set_value("UserData.Switch", "profile_user_id", PROFILE_USER_ID)
    isolated_settings.set_value("UserData.Switch", "profile_account_name", PROFILE_ACCOUNT)
    return isolated_settings


def test_identity(profile):
    emulator = yuzu.Yuzu()

    assert emulator.get_name() == "Yuzu"
    assert emulator.get_platforms() == [
        config.Platform.NINTENDO_SWITCH,
        config.Platform.NINTENDO_SWITCH_ESHOP]
    assert emulator.get_config()["Yuzu"]["program"] == {
        "windows": "Yuzu/windows/yuzu.exe", "linux": "Yuzu/linux/Yuzu.AppImage"}


###########################################################
# Setup
###########################################################

@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_restores_the_stored_early_access_builds(seams, method):
    # There is nothing left to download, so online and offline setup agree
    assert getattr(seams.emulator(), method)() is True

    assert stored_releases(seams) == expected_stored("Yuzu")
    assert seams.releases.values("preferred_archive", "search_file") == [
        ("Windows-Yuzu-EA-4176", "yuzu.exe"), ("Linux-Yuzu-EA-4176", None)]
    assert all(seams.releases.values("skip_if_missing"))


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_passes_the_setup_params_through(seams, method):
    check_passes_the_setup_params_through(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
def test_setup_skips_platforms_that_are_not_wanted(seams, method):
    check_skips_platforms_that_are_not_wanted(seams, method)


@pytest.mark.parametrize("method", SETUP_METHODS)
@pytest.mark.parametrize("failing_call", [1, 2])
def test_setup_stops_at_the_first_failure(seams, method, failing_call):
    check_stops_at_the_failed_call(seams, method, failing_call)


###########################################################
# Launch
###########################################################

def test_launch_runs_the_program_on_the_game(seams):
    assert launch_cmd(seams) == ["/bin/Yuzu", "-g", config.token_game_file]


def test_launch_fullscreen_adds_the_fullscreen_flags(seams):
    assert launch_cmd(seams, fullscreen = True)[3:] == ["-f"]


def test_launch_passes_the_game_and_options_through(seams):
    check_launch_passes_the_game_and_options_through(seams)


###########################################################
# Switch profile
###########################################################

def test_the_configured_profile_names_the_save_dir(profile):
    entry = yuzu.Yuzu().get_config()["Yuzu"]

    assert (entry["profile_user_id"], entry["profile_account_name"]) == (PROFILE_USER_ID, PROFILE_ACCOUNT)
    for platform in PLATFORMS:
        assert entry["save_dir"][platform].endswith("/" + PROFILE_USER_ID)


def test_an_invalid_profile_falls_back_to_the_default(isolated_settings):
    isolated_settings.set_value("UserData.Switch", "profile_user_id", "not-hex")
    entry = yuzu.Yuzu().get_config()["Yuzu"]

    assert (entry["profile_user_id"], entry["profile_account_name"]) == (DEFAULT_USER_ID, "yuzu")


###########################################################
# Configure
###########################################################

@pytest.fixture
def profiles(seams, profile):
    seams.profiles = seams.fake(yuzu.nintendo, "create_switch_profiles_dat")
    return seams


def test_configure_writes_every_config_file(profiles):
    check_writes_every_config_file(profiles)


def test_configure_stops_when_a_config_file_cannot_be_written(profiles):
    profiles.touched.failures.add(1)

    assert profiles.emulator().configure() is False
    assert profiles.profiles.calls == profiles.copied.calls == []


def test_configure_writes_the_profile_for_each_platform(profiles):
    assert profiles.emulator().configure(all_params()) is True

    assert profiles.profiles.values("profiles_file", "user_id", "account_name") == [
        ("/emu/Yuzu/profiles_file/%s" % platform, PROFILE_USER_ID, PROFILE_ACCOUNT) for platform in PLATFORMS]
    assert profiles.profiles.calls[0]["pretend_run"] is True


def test_configure_stops_when_a_profile_cannot_be_written(profiles):
    profiles.profiles.failures.add(1)

    assert profiles.emulator().configure() is False
    assert len(profiles.profiles.calls) == 1
    assert profiles.copied.calls == []


def test_configure_copies_the_keys_and_sysdata_to_each_platform(profiles):
    assert profiles.emulator().configure() is True

    assert profiles.copied.values("dest") == [
        "/emu/Yuzu/setup_dir/%s/%s" % (platform, filename)
        for filename in yuzu.system_files for platform in PLATFORMS]


def test_configure_refuses_keys_with_the_wrong_hash(profiles):
    profiles.hashes["keys/prod.keys"] = BAD_MD5

    assert profiles.emulator().configure() is False
    assert profiles.copied.calls == []


def test_configure_stops_when_a_system_file_cannot_be_copied(profiles):
    profiles.copied.failures.add(1)

    assert profiles.emulator().configure() is False
    assert len(profiles.copied.calls) == 1


###########################################################
# Add-ons
###########################################################

@pytest.fixture
def nsp(seams):
    seams.installed = seams.fake(yuzu.nintendo, "install_switch_nsp")
    return seams


def test_install_addons_installs_each_nsp_into_the_nand(nsp, tmp_path):
    dlc = make_packages(tmp_path / "dlc", "dlc.nsp", "readme.txt")
    update = make_packages(tmp_path / "update", "v1.nsp")

    assert nsp.emulator().install_addons(dlc_dirs = [dlc], update_dirs = [update], pretend_run = True) is True

    assert nsp.installed.values("nsp_file", "nand_dir") == [
        (dlc + "/dlc.nsp", "/emu/Yuzu/setup_dir/None/nand"),
        (update + "/v1.nsp", "/emu/Yuzu/setup_dir/None/nand")]
    assert nsp.installed.calls[0]["pretend_run"] is True


def test_install_addons_stops_at_the_first_failed_nsp(nsp, tmp_path):
    dlc = make_packages(tmp_path / "dlc", "a.nsp")
    update = make_packages(tmp_path / "update", "b.nsp")
    nsp.installed.failures.add(1)

    assert nsp.emulator().install_addons(dlc_dirs = [dlc], update_dirs = [update]) is False
    assert len(nsp.installed.calls) == 1
