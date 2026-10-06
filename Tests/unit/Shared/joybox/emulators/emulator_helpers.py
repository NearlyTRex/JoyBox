# Imports
import os

# Local imports
from joybox import config

###########################################################
# Emulator seams
#
# Every emulator module drives the same handful of collaborators: release
# downloads and restores, program paths, config file writes, locker system
# files (verified by md5, then copied or extracted), and the common launcher.
# Seams replaces all of them with recorders so a test can run setup,
# configure and launch end to end and assert on what was asked for.
###########################################################

PLATFORMS = ["windows", "linux"]

RELEASE_FUNCTIONS = [
    "download_github_release",
    "download_general_release",
    "download_webpage_release",
    "build_appimage_from_source",
    "setup_stored_release",
]

# The argument that says where each kind of release comes from
RELEASE_SOURCES = {
    "download_github_release": "github_repo",
    "download_general_release": "archive_url",
    "download_webpage_release": "webpage_url",
    "build_appimage_from_source": "release_url",
    "setup_stored_release": "archive_dir",
}

BAD_MD5 = "0" * 32


class Recorder:
    # Records the keyword arguments of each call; the call numbers in
    # failures (counted from 1) report failure.
    def __init__(self):
        self.calls = []
        self.failures = set()

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return len(self.calls) not in self.failures

    def tagged(self, tag):
        def record(**kwargs):
            return self(release = tag, **kwargs)
        return record

    def values(self, *keys):
        if len(keys) == 1:
            return [call.get(keys[0]) for call in self.calls]
        return [tuple(call.get(key) for key in keys) for call in self.calls]


class PopupQuit(Exception):
    pass


class Seams:
    def __init__(self, monkeypatch, tmp_path, module):
        self.module = module
        self.monkeypatch = monkeypatch
        self.emulator_class = find_emulator_class(module)
        self.name = self.emulator_class().get_name()
        self.wanted = set(PLATFORMS)
        self.locker_root = tmp_path / "locker"
        self.cache_dir = tmp_path / "cache"
        self.cache_dir.mkdir()
        self.hashes = dict(getattr(module, "system_files", {}))
        self.popups = []

        # Releases share one recorder so their order across functions is kept
        self.releases = Recorder()
        for name in RELEASE_FUNCTIONS:
            monkeypatch.setattr(module.release, name, self.releases.tagged(name))

        programs = module.programs
        monkeypatch.setattr(programs, "should_program_be_installed",
            lambda name, platform: platform in self.wanted)
        monkeypatch.setattr(programs, "get_program_install_dir",
            lambda name, platform: "/install/%s/%s" % (name, platform))
        monkeypatch.setattr(programs, "get_program_backup_dir",
            lambda name, platform: "/backup/%s/%s" % (name, platform))
        monkeypatch.setattr(programs, "get_emulator_path_config_value",
            lambda name, key, platform = None: "/emu/%s/%s/%s" % (name, key, platform))
        monkeypatch.setattr(programs, "get_emulator_program", lambda name, platform = None: "/bin/%s" % name)

        environment = module.emulatorbase.environment
        monkeypatch.setattr(environment, "get_emulators_root_dir", lambda: "/emulators")
        monkeypatch.setattr(environment, "get_locker_gaming_emulator_setup_dir", self.locker)
        monkeypatch.setattr(module.emulatorbase.hashing, "calculate_file_md5", self.md5)

        self.touched = Recorder()
        self.copied = Recorder()
        self.extracted = Recorder()
        self.launched = Recorder()
        if hasattr(module, "fileops"):
            monkeypatch.setattr(module.fileops, "touch_file", self.touched)
            monkeypatch.setattr(module.fileops, "smart_copy", self.copied)
        if hasattr(module, "archive"):
            monkeypatch.setattr(module.archive, "extract_archive", self.extracted)
        if hasattr(module, "emulatorcommon"):
            monkeypatch.setattr(module.emulatorcommon, "simple_launch", self.launched)
        if hasattr(module, "gui"):
            monkeypatch.setattr(module.gui, "display_error_popup", self.popup)

    def fake(self, owner, name):
        # Replaces owner.name with a fresh recorder, for collaborators one module uses alone
        recorder = Recorder()
        self.monkeypatch.setattr(owner, name, recorder)
        return recorder

    def locker(self, name):
        return str(self.locker_root / name)

    def add_locker_file(self, relative):
        target = self.locker_root / self.name / relative
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_bytes(b"")
        return str(target)

    def emulator(self):
        return self.emulator_class()

    def md5(self, src, pretend_run = False, **kwargs):
        if pretend_run:
            return ""
        relative = os.path.relpath(src, self.locker(self.name))
        return self.hashes[relative]

    def popup(self, title_text, message_text):
        self.popups.append(title_text)
        raise PopupQuit()


def find_emulator_class(module):
    # Each emulator module defines exactly one EmulatorBase subclass
    found = [value for value in vars(module).values()
        if isinstance(value, type) and issubclass(value, module.emulatorbase.EmulatorBase)
        and value.__module__ == module.__name__]
    assert len(found) == 1, module.__name__
    return found[0]


class Game:
    def __init__(self, cache_dir = None, platform = None, save_dir = None):
        self.cache_dir = cache_dir
        self.platform = platform
        self.save_dir = save_dir

    def get_local_cache_dir(self):
        return self.cache_dir

    def get_platform(self):
        return self.platform

    def get_save_dir(self):
        return self.save_dir


def make_packages(root, *names):
    # An add-on dir holding empty files with these names
    root.mkdir()
    for name in names:
        (root / name).write_text("")
    return str(root)


def all_params():
    return config.SetupParams(locker_type = "local", verbose = True, pretend_run = True, exit_on_failure = True)


def assert_params_passed(calls, with_locker = False):
    # Every call carries the flags of all_params()
    assert calls
    for call in calls:
        assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)
        if with_locker and call["release"] != "setup_stored_release":
            assert call["locker_type"] == "local"


###########################################################
# Setup
#
# setup downloads or builds each wanted platform's program and setup_offline
# restores it from the backup dir; both stop at the first failure.
###########################################################

SETUP_METHODS = ["setup", "setup_offline"]


def run(seams, method, params = None):
    return getattr(seams.emulator(), method)(params)


def check_passes_the_setup_params_through(seams, method):
    assert run(seams, method, all_params()) is True
    assert_params_passed(seams.releases.calls, with_locker = method == "setup")


def check_skips_platforms_that_are_not_wanted(seams, method):
    seams.wanted.clear()

    assert run(seams, method) is True
    assert seams.releases.calls == []


def check_stops_at_the_failed_call(seams, method, failing_call):
    seams.releases.failures.add(failing_call)

    assert run(seams, method) is False
    assert len(seams.releases.calls) == failing_call


def fetched_releases(seams):
    # (release function, where it fetches from, where it installs) per call
    return [(call["release"], call[RELEASE_SOURCES[call["release"]]], call["install_dir"])
        for call in seams.releases.calls]


def stored_releases(seams):
    return seams.releases.values("release", "archive_dir", "install_dir")


def expected_stored(name, platforms = PLATFORMS):
    return [("setup_stored_release", "/backup/%s/%s" % (name, platform), "/install/%s/%s" % (name, platform))
        for platform in platforms]


###########################################################
# Configure
#
# configure writes every config file under the emulators root, then verifies
# the locker system files by md5 and copies or extracts them into each
# platform's setup dir.
###########################################################

def check_writes_every_config_file(seams):
    assert seams.emulator().configure() is True

    assert seams.touched.values("src", "contents") == [
        ("/emulators/%s" % name, contents.strip()) for name, contents in seams.module.config_files.items()]


def check_stops_when_a_config_file_cannot_be_written(seams):
    seams.touched.failures.add(1)

    assert seams.emulator().configure() is False
    assert len(seams.touched.calls) == 1
    assert seams.copied.calls == seams.extracted.calls == []


def check_configure_passes_the_setup_params_through(seams):
    assert seams.emulator().configure(all_params()) is True
    for recorder in (seams.touched, seams.copied, seams.extracted):
        for call in recorder.calls:
            assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)


def check_copies_system_files_to_each_platform(seams):
    assert seams.emulator().configure() is True

    assert seams.copied.values("src", "dest") == [
        (seams.locker(seams.name) + "/" + filename, "/emu/%s/setup_dir/%s/%s" % (seams.name, platform, filename))
        for filename in seams.module.system_files for platform in PLATFORMS]


def check_refuses_a_system_file_with_the_wrong_hash(seams):
    seams.hashes[list(seams.hashes)[-1]] = BAD_MD5

    assert seams.emulator().configure() is False
    assert seams.copied.calls == seams.extracted.calls == []


def check_stops_when_a_system_file_cannot_be_copied(seams):
    seams.copied.failures.add(1)

    assert seams.emulator().configure() is False
    assert len(seams.copied.calls) == 1


def check_extracts_present_archives_to_each_platform(seams, objects):
    for obj in objects:
        seams.add_locker_file(obj + ".zip")

    assert seams.emulator().configure() is True

    assert seams.extracted.values("archive_file", "extract_dir") == [
        (seams.locker(seams.name) + "/" + obj + ".zip", "/emu/%s/setup_dir/%s/%s" % (seams.name, platform, obj))
        for platform in PLATFORMS for obj in objects]
    assert all(call["skip_existing"] for call in seams.extracted.calls)


def check_skips_archives_missing_from_the_locker(seams):
    assert seams.emulator().configure() is True
    assert seams.extracted.calls == []


def check_stops_when_an_archive_cannot_be_extracted(seams, objects):
    for obj in objects:
        seams.add_locker_file(obj + ".zip")
    seams.extracted.failures.add(1)

    assert seams.emulator().configure() is False
    assert len(seams.extracted.calls) == 1


###########################################################
# Launch
###########################################################

def launch(seams, game = None, **kwargs):
    game = game or Game(str(seams.cache_dir))
    assert seams.emulator().launch(game, **kwargs) is True
    assert len(seams.launched.calls) == 1
    return seams.launched.calls[0]


def launch_cmd(seams, game = None, **kwargs):
    return launch(seams, game, **kwargs)["launch_cmd"]


def check_launch_passes_the_game_and_options_through(seams, game = None):
    game = game or Game(str(seams.cache_dir))
    launched = launch(seams, game, capture_type = "video", capture_file = "/cap.mp4",
        verbose = True, pretend_run = True, exit_on_failure = True)

    assert launched["game_info"] is game
    assert (launched["capture_type"], launched["capture_file"]) == ("video", "/cap.mp4")
    assert (launched["verbose"], launched["pretend_run"], launched["exit_on_failure"]) == (True, True, True)
