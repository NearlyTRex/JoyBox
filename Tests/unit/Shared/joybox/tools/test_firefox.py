# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.tools import firefox


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

    assert firefox.find_default_profile_dir([root]) == os.path.join(root, "abcd1234.default-release")


def test_without_an_install_section_the_default_flag_is_used(tmp_path):
    root = make_root(tmp_path, "firefox",
        "[Profile0]\nName=default\nIsRelative=1\nPath=only.default\nDefault=1\n", ["only.default"])

    assert firefox.find_default_profile_dir([root]) == os.path.join(root, "only.default")


def test_an_absolute_profile_path_is_used_as_written(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root = make_root(tmp_path, "firefox", "[Install1]\nDefault=%s\n" % elsewhere)

    assert firefox.find_default_profile_dir([root]) == str(elsewhere)


@pytest.mark.parametrize("profiles_ini", [
    "[Profile0]\nName=default\nPath=unflagged.default\n",
    "not an ini file\n",
    "",
])
def test_a_root_without_a_default_profile_is_passed_over(tmp_path, profiles_ini):
    first = make_root(tmp_path, "first", profiles_ini, ["unflagged.default"])
    second = make_root(tmp_path, "second", "[Install1]\nDefault=found.default\n", ["found.default"])

    assert firefox.find_default_profile_dir([first, second]) == os.path.join(second, "found.default")


def test_a_named_profile_that_is_missing_is_not_used(tmp_path):
    root = make_root(tmp_path, "firefox", "[Install1]\nDefault=deleted.default\n")

    assert firefox.find_default_profile_dir([root]) == ""


def test_no_firefox_means_no_profile(tmp_path):
    assert firefox.find_default_profile_dir([str(tmp_path / "absent")]) == ""


def test_snap_and_flatpak_installs_are_looked_in_too(monkeypatch):
    monkeypatch.setattr(firefox.platform_info, "is_windows_platform", lambda: False)
    home = os.path.expanduser("~")

    assert firefox.get_profile_roots() == [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ]


def test_windows_looks_in_the_roaming_app_data(monkeypatch):
    monkeypatch.setattr(firefox.platform_info, "is_windows_platform", lambda: True)
    monkeypatch.setenv("APPDATA", "C:\\Users\\testuser\\AppData\\Roaming")

    assert firefox.get_profile_roots() == [os.path.join("C:\\Users\\testuser\\AppData\\Roaming", "Mozilla", "Firefox")]


###########################################################
# The tool's config
###########################################################

def test_a_blank_setting_uses_the_profile_firefox_opens(isolated_settings, monkeypatch):
    isolated_settings.set_value("Tools.Firefox", "firefox_profile_dir", "")
    monkeypatch.setattr(firefox, "find_default_profile_dir", lambda: "/found/profile")

    assert firefox.Firefox().get_config()["Firefox"]["profile_dir"] == "/found/profile"


def test_a_set_profile_wins_over_the_one_found(isolated_settings, monkeypatch, tmp_path):
    isolated_settings.set_value("Tools.Firefox", "firefox_profile_dir", str(tmp_path))
    monkeypatch.setattr(firefox, "find_default_profile_dir", lambda: "/found/profile")

    assert firefox.Firefox().get_config()["Firefox"]["profile_dir"] == str(tmp_path)
