# Imports
import importlib.util
import os
import stat

# Local imports
from joybox import default_settings
from joybox import platform_info


###########################################################
# Default settings
#
# bootstrap.py writes this file when none exists, so whether the write
# succeeded has to be answerable - a silently empty config reads back as
# every setting unset.
###########################################################

def read(path):
    with open(path, "r", encoding = "utf-8") as handle:
        return handle.read()


def load_defaults_for(monkeypatch, windows, linux):
    # Fresh copy of the module, so the shared one keeps the host's defaults
    monkeypatch.setattr(platform_info, "is_windows_platform", lambda: windows)
    monkeypatch.setattr(platform_info, "is_linux_platform", lambda: linux)
    spec = importlib.util.spec_from_file_location("default_settings_copy", default_settings.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ini_defaults


###########################################################
# Platform defaults
###########################################################

def test_windows_defaults_use_windows_paths_and_tools(monkeypatch):
    defaults = load_defaults_for(monkeypatch, windows = True, linux = False)

    assert defaults["UserData.Dirs"]["tools_dir"] == "%USERPROFILE%\\Tools"
    assert defaults["UserData.Share"]["locker_gdrive_mount_path"] == "%USERPROFILE%\\LockerGdrive"
    assert defaults["UserData.Share"]["locker_external_mount_path"] == "E:\\"
    assert defaults["Tools.Python"]["python_exe"] == "python.exe"
    assert defaults["Tools.System"] == {"editor": "notepad.exe"}
    assert "Tools.WinGet" in defaults and "Tools.Sandboxie" in defaults
    for section in ("Tools.Apt", "Tools.Snap", "Tools.Flatpak", "Tools.Wine", "Tools.FuseISO"):
        assert section not in defaults


def test_windows_defaults_hold_no_unix_home_paths(monkeypatch):
    # Absolute unix paths remain for server-side and remote settings
    defaults = load_defaults_for(monkeypatch, windows = True, linux = False)

    for section, values in defaults.items():
        for key, value in values.items():
            assert "$HOME" not in value, (section, key)


def test_linux_defaults_use_unix_paths_and_tools(monkeypatch):
    defaults = load_defaults_for(monkeypatch, windows = False, linux = True)

    assert defaults["UserData.Dirs"]["tools_dir"] == "$HOME/Tools"
    assert defaults["UserData.Share"]["locker_external_mount_path"] == "/mnt/external"
    assert defaults["Tools.FuseISO"]["fuseiso_exe"] == "fuseiso"
    assert "Tools.Wine" in defaults and "Tools.Apt" in defaults
    assert "Tools.WinGet" not in defaults and "Tools.Sandboxie" not in defaults


def test_mac_defaults_skip_the_linux_only_tools(monkeypatch):
    defaults = load_defaults_for(monkeypatch, windows = False, linux = False)

    assert "Tools.FuseISO" not in defaults
    assert defaults["Tools.Curl"]["curl_exe"] == "curl"


###########################################################
# Generating the content
###########################################################

def test_an_unknown_section_is_skipped():
    content = default_settings.generate_default_config_content(["No.Such.Section", "UserData.Switch"])

    assert "No.Such.Section" not in content
    assert "[UserData.Switch]" in content
    assert content.startswith(default_settings.CONFIG_HEADER)


def test_a_set_default_is_written_as_an_assignment():
    content = default_settings.generate_default_config_content(["UserData.Switch"])

    assert "profile_account_name = yuzu\n" in content


def test_every_default_section_is_written(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    default_settings.create_default_config_file(path)

    contents = read(path)
    for section in default_settings.ini_defaults:
        assert "[%s]" % section in contents


def test_only_the_named_sections_are_written(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    default_settings.create_default_config_file(path, sections = ["UserData.Servers"])

    contents = read(path)
    assert "[UserData.Servers]" in contents
    assert "[UserData.Dirs]" not in contents


def test_an_empty_default_is_written_as_a_comment(tmp_path):
    # An unset value has to round-trip as unset, not as the empty string
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    default_settings.create_default_config_file(path, sections = ["UserData.Servers"])

    assert "; server_0_host = " in read(path)


###########################################################
# Reporting the outcome
###########################################################

def test_a_written_file_reports_success(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    assert default_settings.create_default_config_file(path) is True


def test_a_missing_parent_directory_is_created(tmp_path):
    path = os.path.join(str(tmp_path), "nested", "deeper", "JoyBox.ini")

    assert default_settings.create_default_config_file(path) is True
    assert os.path.isfile(path)


def test_a_file_that_cannot_be_written_reports_failure(tmp_path):
    # bootstrap.py quits on this rather than carrying on with no settings
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(str(locked), stat.S_IRUSR | stat.S_IXUSR)
    path = os.path.join(str(locked), "JoyBox.ini")

    try:
        assert default_settings.create_default_config_file(path) is False
    finally:
        os.chmod(str(locked), stat.S_IRWXU)


def test_a_pretend_run_writes_nothing(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    assert default_settings.create_default_config_file(path, pretend_run = True) is True
    assert not os.path.exists(path)
