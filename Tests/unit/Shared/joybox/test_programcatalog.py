# Imports
import os
import tomllib

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import programcatalog
from joybox.nintendo import switchprofile


###########################################################
# Program catalog
#
# Every tool's and emulator's data lives in programdata/ as a program.toml and
# template files, read by programs.py without importing any tool or emulator.
# A lookup hands back fresh values, and a placeholder is filled in from the
# settings ini each time it is asked for.
###########################################################

FAMILIES = [programcatalog.FAMILY_TOOLS, programcatalog.FAMILY_EMULATORS]
KNOWN_KEYS = {"config", "config_files", "system_files", "only_on", "program_unknown_when_unset", "platforms", "setup", "setup_offline"}


def all_programs():
    return [(family, name) for family in FAMILIES for name in programcatalog.load_family(family)]


def read_data(family, name):
    with open(os.path.join(programcatalog.get_family_dir(family), name, "program.toml"), "rb") as handle:
        return tomllib.load(handle)


###########################################################
# The data files
###########################################################

@pytest.mark.parametrize("family, name", all_programs())
def test_a_program_file_holds_only_known_keys(family, name):
    assert set(read_data(family, name)) <= KNOWN_KEYS


@pytest.mark.parametrize("family, name", all_programs())
def test_every_template_named_exists_and_every_file_is_named(family, name):
    named = {entry["template"] for entry in read_data(family, name).get("config_files", []) if "template" in entry}
    present = set(os.listdir(os.path.join(programcatalog.get_family_dir(family), name))) - {"program.toml"}

    assert named == present


def strings_in(value):
    if isinstance(value, dict):
        return [text for item in value.values() for text in strings_in(item)]
    if isinstance(value, list):
        return [text for item in value for text in strings_in(item)]
    return [value] if isinstance(value, str) else []


@pytest.mark.parametrize("family, name", all_programs())
def test_every_placeholder_is_filled_in(family, name, isolated_settings, monkeypatch):
    monkeypatch.setattr(programcatalog.platform_info, "is_wine_platform", lambda: True)
    monkeypatch.setattr(programcatalog.platform_info, "is_sandboxie_platform", lambda: True)

    assert [text for text in strings_in(programcatalog.get_config(family, name)) if "{" in text] == []


###########################################################
# Lookups
###########################################################

def test_a_tool_is_looked_up_by_its_name():
    assert programcatalog.get_tool_config("FFMpeg")["FFMpeg"]["program"]["linux"] == "FFMpeg/linux/ffmpeg"


def test_an_emulator_plays_the_platforms_its_data_lists():
    assert programcatalog.get_emulator_platforms("Dolphin") == [
        config.Platform.NINTENDO_GAMECUBE, config.Platform.NINTENDO_WII, config.Platform.NINTENDO_WIIWARE]


def test_an_emulator_whose_data_lists_no_platforms_plays_none():
    assert programcatalog.get_emulator_platforms("BlastEm") == []


def test_an_unknown_emulator_plays_no_platforms():
    assert programcatalog.get_emulator_platforms("NotAnEmulator") == []


def test_an_unknown_program_has_no_data():
    assert (programcatalog.get_tool_config("NotATool"), programcatalog.get_config_files("tools", "NotATool"),
            programcatalog.get_system_files("emulators", "NotAnEmulator")) == ({}, {}, {})


def test_a_lookup_hands_back_fresh_values():
    programcatalog.get_tool_config("FFMpeg")["FFMpeg"]["program"]["linux"] = "changed"

    assert programcatalog.get_tool_config("FFMpeg")["FFMpeg"]["program"]["linux"] == "FFMpeg/linux/ffmpeg"


def test_none_stands_for_a_value_that_is_not_set():
    assert programcatalog.get_emulator_config("Ares")["Ares"]["save_dir"] == {"windows": None, "linux": None}


def test_a_placeholder_follows_the_settings(isolated_settings):
    isolated_settings.set_value("Tools.Git", "git_exe", "git")
    isolated_settings.set_value("Tools.Git", "git_install_dir", "/first")
    first = programcatalog.get_tool_config("Git")["Git"]["program"]
    isolated_settings.set_value("Tools.Git", "git_install_dir", "/second")

    assert (first, programcatalog.get_tool_config("Git")["Git"]["program"]) == ("/first/git", "/second/git")


def test_a_single_placeholder_is_the_setting_as_written(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "/venv")

    assert programcatalog.get_tool_config("Python")["Python"]["venv_dir"] == "/venv"


def test_a_program_only_on_a_platform_is_absent_elsewhere(monkeypatch):
    monkeypatch.setattr(programcatalog.platform_info, "is_wine_platform", lambda: False)

    assert programcatalog.get_tool_config("Wine") == {}


def test_an_unset_setting_leaves_a_program_unknown_when_asked_to(monkeypatch, isolated_settings):
    monkeypatch.setattr(programcatalog.platform_info, "is_sandboxie_platform", lambda: True)
    isolated_settings.set_value("Tools.Sandboxie", "sandboxie_install_dir", "")

    assert programcatalog.get_tool_config("Sandboxie")["Sandboxie"]["program"] is None


def test_an_unknown_placeholder_is_an_error():
    with pytest.raises(ValueError, match = "Unknown placeholder"):
        programcatalog.fill_value("{nonsense}", {})


def test_an_unknown_platform_condition_is_an_error():
    with pytest.raises(ValueError, match = "Unknown only_on"):
        programcatalog.is_present({"only_on": "amiga"})


def test_config_files_come_in_order_with_their_templates():
    files = programcatalog.get_config_files("emulators", "DuckStation")

    assert list(files)[0] == "DuckStation/windows/portable.txt" and files["DuckStation/windows/portable.txt"] == ""
    assert "[Main]" in files["DuckStation/windows/settings.ini"]


def test_system_files_are_listed_with_their_md5():
    assert programcatalog.get_system_files("emulators", "DuckStation")["bios/scph5500.bin"] == "8dd7d5296a650fac7319bce665a6a53c"


###########################################################
# Yuzu's Switch profile
###########################################################

VALID_ID = "F6F389D41D6BC0BDD6BD928C526AE557"


def test_an_emulator_is_looked_up_by_its_name():
    assert programcatalog.get_emulator_config("A7800")["A7800"]["run_sandboxed"] == {"windows": False, "linux": True}


def test_an_unknown_emulator_has_no_config():
    assert programcatalog.get_emulator_config("NotAnEmulator") == {}


def test_a_lookup_hands_back_a_copy():
    programcatalog.get_emulator_config("A7800")["A7800"]["run_sandboxed"]["linux"] = False

    assert programcatalog.get_emulator_config("A7800")["A7800"]["run_sandboxed"]["linux"] is True


def test_yuzu_uses_the_switch_profile_from_the_settings(isolated_settings):
    isolated_settings.set_value("UserData.Switch", "profile_user_id", VALID_ID)
    isolated_settings.set_value("UserData.Switch", "profile_account_name", "player")
    yuzu = programcatalog.get_emulator_config("Yuzu")["Yuzu"]

    assert (yuzu["profile_user_id"], yuzu["profile_account_name"]) == (VALID_ID, "player")
    assert yuzu["save_dir"]["linux"].endswith("/" + VALID_ID)


def test_yuzu_falls_back_to_its_own_profile_without_a_valid_one(isolated_settings, monkeypatch):
    warnings = []
    monkeypatch.setattr(programcatalog.logger, "log_warning", warnings.append)
    isolated_settings.set_value("UserData.Switch", "profile_user_id", "not an id")
    yuzu = programcatalog.get_emulator_config("Yuzu")["Yuzu"]

    assert switchprofile.is_valid_switch_profile_info(yuzu["profile_user_id"], yuzu["profile_account_name"])
    assert yuzu["profile_account_name"] == "yuzu"
    assert warnings == ["No Switch profile found in ini, using default"]


###########################################################
# Finding the profile
#
# Firefox names each machine's profile at random, so the one it opens is read
# from its own profiles.ini rather than kept in the settings.
###########################################################

INSTALL_AND_FLAG = """[Install4F96D1932A9F858E]
Default=abcd1234.default-release
Locked=1

[Profile1]
Name=default
IsRelative=1
Path=wxyz9876.default
Default=1

[Profile0]
Name=default-release
IsRelative=1
Path=abcd1234.default-release
"""


def make_root(tmp_path, name, profiles_ini, profiles = ()):
    root = tmp_path / name
    root.mkdir()
    (root / "profiles.ini").write_text(profiles_ini)
    for profile in profiles:
        (root / profile).mkdir()
    return str(root)


def test_the_install_default_wins_over_the_default_flag(tmp_path):
    # The flag can mark a profile nothing opens, as it does on a desktop
    # Firefox has upgraded.
    root = make_root(tmp_path, "firefox", INSTALL_AND_FLAG, ["abcd1234.default-release", "wxyz9876.default"])

    assert programcatalog.find_default_profile_dir([root]) == os.path.join(root, "abcd1234.default-release")


def test_without_an_install_section_the_default_flag_is_used(tmp_path):
    root = make_root(tmp_path, "firefox",
        "[Profile0]\nName=default\nIsRelative=1\nPath=only.default\nDefault=1\n", ["only.default"])

    assert programcatalog.find_default_profile_dir([root]) == os.path.join(root, "only.default")


def test_an_absolute_profile_path_is_used_as_written(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root = make_root(tmp_path, "firefox", "[Install1]\nDefault=%s\n" % elsewhere)

    assert programcatalog.find_default_profile_dir([root]) == str(elsewhere)


@pytest.mark.parametrize("profiles_ini", [
    "[Profile0]\nName=default\nPath=unflagged.default\n",
    "not an ini file\n",
    "",
])
def test_a_root_without_a_default_profile_is_passed_over(tmp_path, profiles_ini):
    first = make_root(tmp_path, "first", profiles_ini, ["unflagged.default"])
    second = make_root(tmp_path, "second", "[Install1]\nDefault=found.default\n", ["found.default"])

    assert programcatalog.find_default_profile_dir([first, second]) == os.path.join(second, "found.default")


def test_a_named_profile_that_is_missing_is_not_used(tmp_path):
    root = make_root(tmp_path, "firefox", "[Install1]\nDefault=deleted.default\n")

    assert programcatalog.find_default_profile_dir([root]) == ""


def test_no_firefox_means_no_profile(tmp_path):
    assert programcatalog.find_default_profile_dir([str(tmp_path / "absent")]) == ""


def test_snap_and_flatpak_installs_are_looked_in_too(monkeypatch):
    monkeypatch.setattr(programcatalog.platform_info, "is_windows_platform", lambda: False)
    home = os.path.expanduser("~")

    assert programcatalog.get_profile_roots() == [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ]


def test_windows_looks_in_the_roaming_app_data(monkeypatch):
    monkeypatch.setattr(programcatalog.platform_info, "is_windows_platform", lambda: True)
    monkeypatch.setenv("APPDATA", "C:\\Users\\testuser\\AppData\\Roaming")

    assert programcatalog.get_profile_roots() == [os.path.join("C:\\Users\\testuser\\AppData\\Roaming", "Mozilla", "Firefox")]


def test_a_program_lists_its_setup_and_offline_setup_steps():
    online = programcatalog.get_setup_steps("emulators", "Dolphin")
    offline = programcatalog.get_setup_steps("emulators", "Dolphin", offline = True)

    assert [step["kind"] for step in online] == ["webpage_release", "appimage_build"]
    assert [step["kind"] for step in offline] == ["stored_release", "stored_release"]


def test_an_unknown_program_has_no_setup_steps():
    assert programcatalog.get_setup_steps("tools", "NotATool") == []
