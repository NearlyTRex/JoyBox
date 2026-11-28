# Imports
import pytest

# Local imports
from joybox import config
from joybox import emulatorbase


###########################################################
# EmulatorBase
#
# Resolves an emulator's paths out of its config dict. get_save_dir is the one
# with real branching: a per-platform sub directory when the emulator keeps
# saves in one tree, otherwise a flat save_dir.
###########################################################

ROOT = "/emulators"


@pytest.fixture
def emulator_root(monkeypatch):
    monkeypatch.setattr(
        emulatorbase.environment, "get_emulators_root_dir", lambda: ROOT)
    monkeypatch.setattr(
        emulatorbase.platform_info, "get_current_platform", lambda: "linux")
    return ROOT


# The base with only its abstract steps filled in, to see the defaults
class Bare(emulatorbase.EmulatorBase):
    def setup(self, setup_params = None):
        return True

    def setup_offline(self, setup_params = None):
        return True


def build(config_values, name = "TestMulator", platforms = None):
    class TestEmulator(Bare):
        def get_name(self):
            return name

        def get_platforms(self):
            return platforms or []

        def get_config(self):
            return {name: config_values}

    return TestEmulator()


###########################################################
# Defaults
###########################################################

def test_the_base_emulator_is_anonymous():
    assert Bare().get_name() == ""


def test_the_base_emulator_claims_no_platforms():
    assert Bare().get_platforms() == []


def test_the_base_emulator_has_no_config():
    assert Bare().get_config() == {}


def test_the_base_emulator_has_no_save_type():
    assert Bare().get_save_type() is None


def test_the_base_emulator_sets_up_by_its_program_data(monkeypatch):
    calls = []
    monkeypatch.setattr(emulatorbase.programsetup, "run_setup_steps",
        lambda family, name, offline = False, setup_params = None: calls.append((family, name, offline)) or True)

    base = emulatorbase.EmulatorBase()

    assert (base.setup(), base.setup_offline()) == (True, True)
    assert calls == [("emulators", "", False), ("emulators", "", True)]


def test_the_base_emulator_configure_step_succeeds_as_a_no_op():
    assert Bare().configure() is True


def test_the_base_emulator_cannot_launch_anything():
    assert Bare().launch(game_info = None) is False


def test_the_base_emulator_installs_addons_successfully():
    # Most emulators have no addons; the default must not report failure.
    assert Bare().install_addons() is True


def test_the_base_emulator_installs_each_addon_dir_as_a_no_op():
    assert Bare().install_addons(dlc_dirs = ["/dlc"], update_dirs = ["/update"]) is True


###########################################################
# Path resolution
###########################################################

def test_a_config_file_is_resolved_under_the_emulator_root(emulator_root):
    emulator = build({"config_file": {"linux": "TestMulator/config.ini"}})

    assert emulator.get_config_file() == "/emulators/TestMulator/config.ini"


def test_a_setup_dir_is_resolved_under_the_emulator_root(emulator_root):
    emulator = build({"setup_dir": {"linux": "TestMulator/setup"}})

    assert emulator.get_setup_dir() == "/emulators/TestMulator/setup"


def test_a_missing_config_file_entry_resolves_to_nothing(emulator_root):
    assert build({}).get_config_file() is None


def test_a_requested_platform_selects_its_entry(emulator_root):
    emulator = build({"config_file": {
        "linux": "TestMulator/linux.ini",
        "windows": "TestMulator/windows.ini",
    }})

    assert emulator.get_config_file("windows") == "/emulators/TestMulator/windows.ini"


###########################################################
# Save directories
###########################################################

def test_a_flat_save_dir_is_used(emulator_root):
    emulator = build({"save_dir": {"linux": "TestMulator/saves"}})

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/saves"


def test_a_platform_sub_dir_is_appended_to_the_base(emulator_root):
    emulator = build({
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/User/NES/saves"


def test_a_sub_dir_wins_over_a_flat_save_dir(emulator_root):
    # An emulator declaring both keeps per-platform saves apart.
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/User/NES/saves"


def test_an_uncovered_platform_falls_back_to_the_flat_save_dir(emulator_root):
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("sega_genesis") == "/emulators/TestMulator/saves"


def test_an_uncovered_platform_without_a_fallback_resolves_to_nothing(emulator_root):
    # This is what the registry sweep guards against: a silent no save dir.
    emulator = build({
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("sega_genesis") is None


def test_a_base_dir_without_sub_dirs_is_not_used_alone(emulator_root):
    # The base is a container, not a save location.
    emulator = build({"save_base_dir": {"linux": "TestMulator/User"}})

    assert emulator.get_save_dir("nintendo_nes") is None


def test_sub_dirs_without_a_base_dir_fall_back(emulator_root):
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/saves"


def test_no_game_platform_falls_back_to_the_flat_save_dir(emulator_root):
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir(None) == "/emulators/TestMulator/saves"


def test_an_emulator_managing_no_saves_resolves_to_nothing(emulator_root):
    # A None save dir means JoyBox does not manage this emulator's saves.
    assert build({}).get_save_dir("nintendo_nes") is None


def test_the_emulator_platform_selects_the_sub_dir_table(emulator_root):
    emulator = build({
        "save_base_dir": {
            "linux": "TestMulator/linux",
            "windows": "TestMulator/windows",
        },
        "save_sub_dirs": {
            "linux": {"nintendo_nes": "NES/saves"},
            "windows": {"nintendo_nes": "NES\\saves"},
        },
    })

    assert emulator.get_save_dir("nintendo_nes", "windows").startswith(
        "/emulators/TestMulator/windows")


def test_the_current_platform_is_used_when_none_is_given(monkeypatch, emulator_root):
    monkeypatch.setattr(
        emulatorbase.platform_info, "get_current_platform", lambda: "windows")
    emulator = build({"save_dir": {
        "linux": "TestMulator/linux-saves",
        "windows": "TestMulator/windows-saves",
    }})

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/windows-saves"


def test_save_sub_dirs_are_read_as_a_mapping(emulator_root):
    emulator = build({"save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}}})

    assert emulator.get_save_sub_dirs() == {"nintendo_nes": "NES/saves"}


def test_a_missing_sub_dir_table_reads_as_nothing(emulator_root):
    assert build({}).get_save_sub_dirs() is None


def test_a_save_base_dir_is_resolved_under_the_emulator_root(emulator_root):
    emulator = build({"save_base_dir": {"linux": "TestMulator/User"}})

    assert emulator.get_save_base_dir() == "/emulators/TestMulator/User"


###########################################################
# System file verification
###########################################################

SYSTEM_FILES = {"bios/a.bin": "aaaa", "bios/b.bin": "bbbb"}


@pytest.fixture
def locker_hashes(monkeypatch):
    hashes = {"/locker/TestMulator/bios/a.bin": "aaaa", "/locker/TestMulator/bios/b.bin": "bbbb"}
    reads = []

    def md5(src, pretend_run = False, **kwargs):
        reads.append(src)
        return "" if pretend_run else hashes[src]

    monkeypatch.setattr(emulatorbase.environment, "get_locker_gaming_emulator_setup_dir",
        lambda name: "/locker/%s" % name)
    monkeypatch.setattr(emulatorbase.hashutil, "calculate_file_md5", md5)
    return {"hashes": hashes, "reads": reads}


def test_matching_system_files_verify(locker_hashes):
    assert build({}).verify_system_files(SYSTEM_FILES, config.SetupParams()) is True
    assert locker_hashes["reads"] == list(locker_hashes["hashes"])


def test_a_mismatched_system_file_fails_verification(locker_hashes):
    locker_hashes["hashes"]["/locker/TestMulator/bios/a.bin"] = "ffff"

    assert build({}).verify_system_files(SYSTEM_FILES, config.SetupParams()) is False
    assert locker_hashes["reads"] == ["/locker/TestMulator/bios/a.bin"]


def test_a_pretend_verification_passes_without_real_hashes(locker_hashes):
    params = config.SetupParams(pretend_run = True)

    assert build({}).verify_system_files(SYSTEM_FILES, params) is True


###########################################################
# Config files
###########################################################

@pytest.fixture
def touched(monkeypatch, emulator_root):
    calls = []
    state = {"ok": True}

    def touch_file(src, contents, **kwargs):
        calls.append((src, contents))
        return state["ok"]

    monkeypatch.setattr(emulatorbase.fileops, "touch_file", touch_file)
    return {"calls": calls, "state": state}


def with_config_files(files):
    emulator = build({})
    emulator.get_config_files = lambda: files
    return emulator


def test_config_files_are_written_stripped_under_the_emulator_root(touched):
    assert with_config_files({"a.ini": " a \n", "b.ini": "b"}).write_config_files() is True
    assert touched["calls"] == [(ROOT + "/a.ini", "a"), (ROOT + "/b.ini", "b")]


def test_a_failed_config_file_stops_and_logs_its_label(touched, monkeypatch):
    errors = []
    monkeypatch.setattr(emulatorbase.logger, "log_error", errors.append)
    touched["state"]["ok"] = False

    assert with_config_files({"a.ini": "a", "b.ini": "b"}).write_config_files(label = "Pair") is False
    assert len(touched["calls"]) == 1
    assert errors == ["Could not setup Pair config files"]


###########################################################
# System archives
###########################################################

@pytest.fixture
def system_archive(monkeypatch, tmp_path):
    extracted = []
    state = {"ok": True}

    def extract_archive(archive_file, extract_dir, **kwargs):
        extracted.append((archive_file, extract_dir, kwargs["skip_existing"]))
        return state["ok"]

    monkeypatch.setattr(emulatorbase.environment, "get_locker_gaming_emulator_setup_dir", lambda name: str(tmp_path))
    monkeypatch.setattr(emulatorbase.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: "/emu/%s/%s/%s" % (name, key, platform))
    monkeypatch.setattr(emulatorbase.archive, "extract_archive", extract_archive)
    return {"root": tmp_path, "extracted": extracted, "state": state}


def test_a_missing_system_archive_is_skipped(system_archive):
    assert build({}).extract_system_archive("linux", "nand", config.SetupParams()) is True
    assert system_archive["extracted"] == []


def test_a_system_archive_unzips_into_the_platform_setup_dir(system_archive):
    archive_file = system_archive["root"] / "nand.zip"
    archive_file.write_text("zip")

    assert build({}).extract_system_archive("linux", "nand", config.SetupParams()) is True
    assert system_archive["extracted"] == [(str(archive_file), "/emu/TestMulator/setup_dir/linux/nand", True)]


def test_a_failed_system_archive_extraction_fails(system_archive):
    (system_archive["root"] / "nand.zip").write_text("zip")
    system_archive["state"]["ok"] = False

    assert build({}).extract_system_archive("linux", "nand", config.SetupParams()) is False


def test_system_archives_unzip_into_each_platform_in_turn(system_archive):
    emulator = build({})
    emulator.SYSTEM_ARCHIVES = ("nand", "sysdata")
    for obj in emulator.SYSTEM_ARCHIVES:
        (system_archive["root"] / (obj + ".zip")).write_text("zip")

    assert emulator.extract_system_archives(config.SetupParams()) is True
    assert [extract_dir for _, extract_dir, _ in system_archive["extracted"]] == [
        "/emu/TestMulator/setup_dir/windows/nand", "/emu/TestMulator/setup_dir/windows/sysdata",
        "/emu/TestMulator/setup_dir/linux/nand", "/emu/TestMulator/setup_dir/linux/sysdata"]


def test_verified_system_files_are_unzipped_instead_of_copied_when_archives_are_named(system_archive, monkeypatch):
    copied = []
    monkeypatch.setattr(emulatorbase.filebulk, "smart_copy", lambda **kwargs: copied.append(kwargs) or True)
    emulator = build({})
    emulator.SYSTEM_ARCHIVES = ("nand",)
    emulator.get_system_files = lambda: {}
    (system_archive["root"] / "nand.zip").write_text("zip")

    assert emulator.install_system_files(config.SetupParams()) is True
    assert len(system_archive["extracted"]) == 2
    assert copied == []


def test_system_files_are_copied_into_each_platform_setup_dir(system_archive, monkeypatch):
    copied = []
    monkeypatch.setattr(emulatorbase.filebulk, "smart_copy", lambda src, dest, **kwargs: copied.append((src, dest)) or True)
    emulator = build({})
    emulator.get_system_files = lambda: {"bios.bin": "md5"}

    assert emulator.copy_system_files(config.SetupParams()) is True
    assert copied == [
        (str(system_archive["root"] / "bios.bin"), "/emu/TestMulator/setup_dir/windows/bios.bin"),
        (str(system_archive["root"] / "bios.bin"), "/emu/TestMulator/setup_dir/linux/bios.bin")]


def test_a_failed_system_file_copy_stops_and_logs(system_archive, monkeypatch):
    errors = []
    monkeypatch.setattr(emulatorbase.filebulk, "smart_copy", lambda **kwargs: False)
    monkeypatch.setattr(emulatorbase.logger, "log_error", errors.append)
    emulator = build({})
    emulator.get_system_files = lambda: {"bios.bin": "md5"}

    assert emulator.copy_system_files(config.SetupParams()) is False
    assert errors == ["Could not setup TestMulator system files"]



###########################################################
# Launching from program data
#
# The command is the program, then its [launch] args with the game tokens and
# platform values filled in, then fullscreen_args when fullscreen.
###########################################################

class FakeGame:
    def __init__(self, platform = "Nintendo 64"):
        self.platform = platform

    def get_platform(self):
        return self.platform


class Prepared(Bare):
    NAME = "TestMulator"

    def __init__(self, prepared = True, values = None):
        self.prepared = prepared
        self.values = values or {}
        self.prepare_calls = []

    def prepare_launch(self, game_info, verbose = False, pretend_run = False, exit_on_failure = False):
        self.prepare_calls.append((game_info, verbose, pretend_run, exit_on_failure))
        return self.prepared

    def get_launch_values(self, game_info):
        return self.values


@pytest.fixture
def launcher(monkeypatch):
    state = {"launch": {"args": ["--system", "{platform_config:systems}", "{game_file}"], "fullscreen_args": ["-f"]},
        "launched": [], "popups": []}
    monkeypatch.setattr(emulatorbase.programcatalog, "get_launch", lambda family, name: state["launch"])
    monkeypatch.setattr(emulatorbase.programs, "get_emulator_program", lambda name: "/bin/%s" % name)
    monkeypatch.setattr(emulatorbase.programs, "get_emulator_config_value", lambda name, key: {"Nintendo 64": "N64"})
    monkeypatch.setattr(emulatorbase.emulatorcommon, "simple_launch", lambda **kwargs: state["launched"].append(kwargs) or True)

    def popup(title_text, message_text):
        state["popups"].append((title_text, message_text))
        raise LookupError(message_text)
    monkeypatch.setattr(emulatorbase.gui, "display_error_popup", popup)
    return state


def test_a_launch_runs_the_program_with_its_filled_in_args(launcher):
    game = FakeGame()

    assert Prepared().launch(game, capture_type = "video", capture_file = "/cap.mp4", verbose = True) is True
    launched = launcher["launched"][0]
    assert launched["launch_cmd"] == ["/bin/TestMulator", "--system", "N64", config.TOKEN_GAME_FILE]
    assert (launched["game_info"], launched["capture_type"], launched["capture_file"], launched["verbose"]) == (game, "video", "/cap.mp4", True)


def test_a_fullscreen_launch_adds_the_fullscreen_args(launcher):
    assert Prepared().get_launch_command(FakeGame(), fullscreen = True)[-1] == "-f"


def test_every_game_token_is_filled_in(launcher):
    launcher["launch"] = {"args": ["{game_file}", "{game_dir}", "{game_name}", "plain"]}

    assert Prepared().get_launch_command(FakeGame())[1:] == [config.TOKEN_GAME_FILE, config.TOKEN_GAME_DIR, config.TOKEN_GAME_NAME, "plain"]


def test_an_emulators_own_launch_values_fill_its_placeholders(launcher):
    launcher["launch"] = {"args": ["-L", "{core_file}", "{game_file}"]}

    assert Prepared(values = {"core_file": "/cores/n64.so"}).get_launch_command(FakeGame())[1:3] == ["-L", "/cores/n64.so"]


def test_a_platform_missing_from_the_config_table_stops_with_a_popup(launcher):
    with pytest.raises(LookupError):
        Prepared().get_launch_command(FakeGame("Sega Saturn"))

    assert launcher["popups"] == [("Launch platform not defined", "Launch platform Sega Saturn not defined in TestMulator config")]


def test_a_failed_preparation_launches_nothing(launcher):
    emulator = Prepared(prepared = False)

    assert emulator.launch(FakeGame(), verbose = True, pretend_run = True, exit_on_failure = True) is False
    assert emulator.prepare_calls[0][1:] == (True, True, True)
    assert launcher["launched"] == []


def test_the_base_needs_no_preparation_or_launch_values():
    assert Bare().prepare_launch(FakeGame()) is True
    assert Bare().get_launch_values(FakeGame()) == {}
