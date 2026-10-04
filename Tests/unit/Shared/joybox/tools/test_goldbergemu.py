# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.tools import goldbergemu

USER_ID = "76561190000000001"
GOLDBERG = "AppData/Roaming/Goldberg SteamEmu Saves"
NATIVE = "Store/Steam/userdata/%s" % USER_ID


###########################################################
# Fakes
###########################################################

class Recorder:
    def __init__(self, results = None):
        self.calls = []
        self.results = list(results or [])

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.results.pop(0) if self.results else True


def write(path, text = "x"):
    path.parent.mkdir(parents = True, exist_ok = True)
    path.write_text(text)


###########################################################
# Libraries
###########################################################

def test_config_lists_the_steam_api_libs():
    tool = goldbergemu.GoldbergEmu()

    assert tool.get_name() == "GoldbergEmu"
    assert tool.get_config() == {"GoldbergEmu": {"lib32": ["steam_api.dll"], "lib64": ["steam_api64.dll"]}}


def test_libs_are_found_by_bitness(monkeypatch, tmp_path):
    write(tmp_path / "x86" / "steam_api.dll")
    write(tmp_path / "x64" / "steam_api64.dll")
    write(tmp_path / "readme.txt")
    monkeypatch.setattr(goldbergemu.programs, "get_library_install_dir", lambda name, platform: str(tmp_path))
    monkeypatch.setattr(goldbergemu.programs, "get_tool_config_value", lambda name, key: goldbergemu.GoldbergEmu().get_config()[name][key])

    assert goldbergemu.get_libs32() == [str(tmp_path / "x86" / "steam_api.dll")]
    assert goldbergemu.get_libs64() == [str(tmp_path / "x64" / "steam_api64.dll")]


###########################################################
# Paths
###########################################################

def test_user_files_live_under_the_prefix_settings():
    assert goldbergemu.generate_username_file("/prefix") == "/prefix/%s/settings/account_name.txt" % GOLDBERG
    assert goldbergemu.generate_userid_file("/prefix") == "/prefix/%s/settings/user_steam_id.txt" % GOLDBERG


def test_native_path_conversion_round_trips():
    native = "General/%s/remote/save.dat" % NATIVE
    goldberg = "General/%s/remote/save.dat" % GOLDBERG

    assert goldbergemu.convert_from_native_path(native, USER_ID) == goldberg
    assert goldbergemu.convert_to_native_path(goldberg, USER_ID) == native


###########################################################
# User files
###########################################################

def test_setup_user_files_writes_name_and_id(tmp_path):
    assert goldbergemu.setup_user_files(str(tmp_path), "player", USER_ID)

    settings_dir = tmp_path / GOLDBERG / "settings"
    assert (settings_dir / "account_name.txt").read_text() == "player\n"
    assert (settings_dir / "user_steam_id.txt").read_text() == "%s\n" % USER_ID


@pytest.mark.parametrize("results", [[False], [True, False]])
def test_setup_user_files_stops_on_a_failed_write(monkeypatch, results):
    touched = Recorder(results)
    monkeypatch.setattr(goldbergemu.fileops, "touch_file", touched)

    assert not goldbergemu.setup_user_files("/prefix", "player", USER_ID)
    assert len(touched.calls) == len(results)


###########################################################
# Save conversion
###########################################################

def test_convert_to_native_save_moves_saves_and_drops_settings(tmp_path):
    write(tmp_path / "General" / GOLDBERG / "480" / "remote" / "save.dat", "slot1")
    write(tmp_path / "General" / GOLDBERG / "settings" / "account_name.txt")

    assert goldbergemu.convert_to_native_save(str(tmp_path), USER_ID)

    assert (tmp_path / "General" / NATIVE / "480" / "remote" / "save.dat").read_text() == "slot1"
    assert not (tmp_path / "General" / "AppData" / "Roaming").exists()


def test_convert_to_native_save_keeps_other_roaming_data(tmp_path):
    write(tmp_path / "General" / GOLDBERG / "480" / "save.dat")
    write(tmp_path / "General" / "AppData" / "Roaming" / "Other" / "keep.dat")

    assert goldbergemu.convert_to_native_save(str(tmp_path), USER_ID)

    assert not (tmp_path / "General" / GOLDBERG).exists()
    assert (tmp_path / "General" / "AppData" / "Roaming" / "Other" / "keep.dat").exists()


def test_convert_to_native_save_stops_on_a_failed_move(monkeypatch, tmp_path):
    write(tmp_path / "General" / GOLDBERG / "480" / "save.dat")
    monkeypatch.setattr(goldbergemu.fileops, "smart_move", Recorder([False]))
    removed = Recorder()
    monkeypatch.setattr(goldbergemu.fileops, "remove_directory", removed)

    assert not goldbergemu.convert_to_native_save(str(tmp_path), USER_ID)
    assert removed.calls == []


@pytest.mark.parametrize("results", [[False], [True, False]])
def test_convert_to_native_save_stops_on_a_failed_cleanup(monkeypatch, tmp_path, results):
    removed = Recorder(results)
    monkeypatch.setattr(goldbergemu.fileops, "remove_directory", removed)

    assert not goldbergemu.convert_to_native_save(str(tmp_path), USER_ID)
    assert len(removed.calls) == len(results)


###########################################################
# Setup
###########################################################

@pytest.fixture
def library(monkeypatch):
    wanted = [True]
    monkeypatch.setattr(goldbergemu.programs, "should_library_be_installed", lambda name: wanted[0])
    monkeypatch.setattr(goldbergemu.programs, "get_library_install_dir", lambda name, platform: "/install/%s" % platform)
    monkeypatch.setattr(goldbergemu.programs, "get_library_backup_dir", lambda name, platform: "/backup/%s" % platform)
    return wanted


@pytest.mark.parametrize("result", [True, False])
def test_setup_downloads_the_library(monkeypatch, library, result):
    download = Recorder([result])
    monkeypatch.setattr(goldbergemu.release, "download_webpage_release", download)

    assert goldbergemu.GoldbergEmu().setup() is result
    assert download.calls[0]["install_dir"] == "/install/lib"
    assert download.calls[0]["backups_dir"] == "/backup/lib"


@pytest.mark.parametrize("result", [True, False])
def test_setup_offline_installs_the_stored_library(monkeypatch, library, result):
    stored = Recorder([result])
    monkeypatch.setattr(goldbergemu.release, "setup_stored_release", stored)

    assert goldbergemu.GoldbergEmu().setup_offline() is result
    assert stored.calls[0]["archive_dir"] == "/backup/lib"


def test_setup_skips_a_library_not_installed(monkeypatch, library):
    library[0] = False
    download = Recorder()
    stored = Recorder()
    monkeypatch.setattr(goldbergemu.release, "download_webpage_release", download)
    monkeypatch.setattr(goldbergemu.release, "setup_stored_release", stored)
    tool = goldbergemu.GoldbergEmu()

    assert tool.setup(config.SetupParams())
    assert tool.setup_offline(config.SetupParams())
    assert download.calls == [] and stored.calls == []
