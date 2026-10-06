# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import vita3k
from fakes import write_param_sfo
from emulator_helpers import (
    SETUP_METHODS, Game, Seams, check_configure_passes_the_setup_params_through,
    check_extracts_present_archives_to_each_platform, check_launch_passes_the_game_and_options_through,
    check_passes_the_setup_params_through, check_refuses_a_system_file_with_the_wrong_hash,
    check_skips_archives_missing_from_the_locker, check_skips_platforms_that_are_not_wanted,
    check_stops_at_the_failed_call, check_stops_when_a_config_file_cannot_be_written,
    check_stops_when_an_archive_cannot_be_extracted, check_writes_every_config_file, expected_stored,
    fetched_releases, launch, launch_cmd, stored_releases)


###########################################################
# Vita3K
#
# A Vita program: both builds come from GitHub releases, and configure extracts
# the verified firmware partitions into each platform's setup dir.
###########################################################

SYSTEM_ARCHIVES = ["os0", "sa0", "vs0"]


@pytest.fixture
def seams(monkeypatch, tmp_path):
    return Seams(monkeypatch, tmp_path, vita3k)


def test_identity():
    emulator = vita3k.Vita3K()

    assert emulator.get_name() == "Vita3K"
    assert emulator.get_platforms() == [
        config.Platform.SONY_PLAYSTATION_NETWORK_PSV,
        config.Platform.SONY_PLAYSTATION_VITA]
    assert emulator.get_config()["Vita3K"]["program"] == {
        "windows": "Vita3K/windows/Vita3K.exe", "linux": "Vita3K/linux/Vita3K.AppImage"}


###########################################################
# Setup
###########################################################

def test_setup_fetches_each_platform_program(seams):
    assert seams.emulator().setup() is True

    assert fetched_releases(seams) == [
        ("download_github_release", "Vita3K", "/install/Vita3K/windows"),
        ("download_github_release", "Vita3K", "/install/Vita3K/linux")]
    assert seams.releases.values("search_file") == ["Vita3K.exe", None]


def test_setup_offline_restores_each_platform_program(seams):
    assert seams.emulator().setup_offline() is True

    assert stored_releases(seams) == expected_stored("Vita3K")
    assert seams.releases.values("search_file") == ["Vita3K.exe", None]


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
# Configure
###########################################################

def test_configure_writes_every_config_file(seams):
    check_writes_every_config_file(seams)


def test_configure_stops_when_a_config_file_cannot_be_written(seams):
    check_stops_when_a_config_file_cannot_be_written(seams)


def test_configure_passes_the_setup_params_through(seams):
    check_configure_passes_the_setup_params_through(seams)


def test_configure_extracts_the_system_archives_to_each_platform(seams):
    check_extracts_present_archives_to_each_platform(seams, SYSTEM_ARCHIVES)


def test_configure_skips_archives_missing_from_the_locker(seams):
    check_skips_archives_missing_from_the_locker(seams)


def test_configure_stops_when_an_archive_cannot_be_extracted(seams):
    check_stops_when_an_archive_cannot_be_extracted(seams, SYSTEM_ARCHIVES)


def test_configure_refuses_a_system_file_with_the_wrong_hash(seams):
    check_refuses_a_system_file_with_the_wrong_hash(seams)


###########################################################
# Launch
#
# The launch name is the title id. An app already in ux0/app runs by id;
# otherwise Vita3K installs and runs the content root found in the game's
# cache, with any root-level work.bin staged into sce_sys/package first.
###########################################################

TITLE_ID = "PCSE00001"


class TitledGame(Game):
    def __init__(self, cache_dir, launch_name = TITLE_ID):
        super().__init__(cache_dir)
        self.launch_name = launch_name

    def get_launch_name(self):
        return self.launch_name


@pytest.fixture
def app_dir(seams, tmp_path):
    app_dir = tmp_path / "ux0" / "app"
    seams.monkeypatch.setattr(vita3k.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: str(app_dir) if key == "app_dir" else "/emu/%s" % key)
    return app_dir


def game(seams, launch_name = TITLE_ID):
    return TitledGame(str(seams.cache_dir), launch_name)


def make_content(seams, title_id = TITLE_ID):
    root = seams.cache_dir / ("EP0001-%s_00-0000000000000000" % title_id)
    write_param_sfo(root / "sce_sys" / "param.sfo", {"TITLE_ID": title_id})
    return root


def stage_root_workbin(seams):
    (seams.cache_dir / "work.bin").write_bytes(b"license")


@pytest.mark.parametrize("launch_name", [None, ""])
def test_launch_without_a_title_id_runs_nothing(seams, app_dir, launch_name):
    assert seams.emulator().launch(game(seams, launch_name)) is False
    assert seams.launched.calls == []


def test_launch_runs_an_installed_app_by_title_id(seams, app_dir):
    (app_dir / TITLE_ID).mkdir(parents = True)
    make_content(seams)

    assert launch_cmd(seams, game(seams)) == ["/bin/Vita3K", "-r", config.token_game_name]


def test_launch_passes_the_game_and_options_through(seams, app_dir):
    (app_dir / TITLE_ID).mkdir(parents = True)

    check_launch_passes_the_game_and_options_through(seams, game(seams))


def test_launch_fullscreen_adds_the_fullscreen_flag(seams, app_dir):
    (app_dir / TITLE_ID).mkdir(parents = True)

    assert launch_cmd(seams, game(seams), fullscreen = True) == [
        "/bin/Vita3K", "-F", "-r", config.token_game_name]


def test_launch_installs_from_the_cached_content_root(seams, app_dir):
    root = make_content(seams)

    assert launch_cmd(seams, game(seams), fullscreen = True) == ["/bin/Vita3K", "-F", str(root)]
    assert not (root / "sce_sys" / "package").exists()


def test_launch_stages_the_root_work_bin_into_the_package_dir(seams, app_dir):
    root = make_content(seams)
    stage_root_workbin(seams)

    assert launch_cmd(seams, game(seams)) == ["/bin/Vita3K", str(root)]
    assert (root / "sce_sys" / "package" / "work.bin").read_bytes() == b"license"


def test_launch_keeps_a_work_bin_the_package_already_has(seams, app_dir):
    root = make_content(seams)
    (root / "sce_sys" / "package").mkdir()
    (root / "sce_sys" / "package" / "work.bin").write_bytes(b"own")
    stage_root_workbin(seams)

    launch(seams, game(seams))

    assert (root / "sce_sys" / "package" / "work.bin").read_bytes() == b"own"


def test_a_pretend_launch_stages_nothing(seams, app_dir):
    root = make_content(seams)
    stage_root_workbin(seams)

    assert launch_cmd(seams, game(seams), pretend_run = True) == ["/bin/Vita3K", str(root)]
    assert not (root / "sce_sys" / "package").exists()


def test_launch_without_app_content_runs_nothing(seams, app_dir):
    (seams.cache_dir / "Game.psv").write_bytes(b"")

    assert seams.emulator().launch(game(seams)) is False
    assert seams.launched.calls == []


@pytest.mark.parametrize("failing", ["make_directory", "copy_file_or_directory"])
def test_launch_stops_when_the_work_bin_cannot_be_staged(seams, app_dir, failing):
    make_content(seams)
    stage_root_workbin(seams)
    seams.monkeypatch.setattr(vita3k.fileops, failing, lambda **kwargs: False)

    assert seams.emulator().launch(game(seams)) is False
    assert seams.launched.calls == []
