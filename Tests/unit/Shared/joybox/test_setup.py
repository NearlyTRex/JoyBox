# Imports
import os
import pytest

# Local imports
from joybox import config, setup


###########################################################
# Requirements
#
# Every command checks these first and exits before doing anything when the
# host cannot run JoyBox.
###########################################################

@pytest.fixture
def host(monkeypatch):
    state = {"windows": False, "linux": True, "symlinks": True, "ini": True}
    monkeypatch.setattr(setup.platform_info, "is_windows_platform", lambda: state["windows"])
    monkeypatch.setattr(setup.platform_info, "is_linux_platform", lambda: state["linux"])
    monkeypatch.setattr(setup.environment, "are_symlinks_supported", lambda: state["symlinks"])
    monkeypatch.setattr(setup.settings, "is_present", lambda: state["ini"])
    return state


def test_a_supported_host_passes(host):
    setup.check_requirements()


def test_a_windows_host_passes(host):
    host.update(windows = True, linux = False)

    setup.check_requirements()


def test_an_old_python_exits(host, monkeypatch):
    monkeypatch.setattr(setup.config, "minimum_python_version", (99, 0, 0))

    with pytest.raises(SystemExit):
        setup.check_requirements()


@pytest.mark.parametrize("change", [
    {"linux": False},
    {"symlinks": False},
    {"ini": False},
])
def test_an_unsupported_host_exits(host, change):
    host.update(change)

    with pytest.raises(SystemExit):
        setup.check_requirements()


###########################################################
# Packages
#
# Packages install in order and stop at the first failure. --clean wipes the
# whole root once; --force wipes only each selected package's own directories.
###########################################################

class Package:
    def __init__(self, name, programs = None, setup_ok = True, configure_ok = True):
        self.name = name
        self.programs = programs if programs is not None else [name]
        self.setup_ok = setup_ok
        self.configure_ok = configure_ok
        self.calls = []

    def get_name(self):
        return self.name

    def get_config(self):
        return {program: {} for program in self.programs}

    def setup(self, setup_params = None):
        self.calls.append(("setup", setup_params))
        return self.setup_ok

    def setup_offline(self, setup_params = None):
        self.calls.append(("setup_offline", setup_params))
        return self.setup_ok

    def configure(self, setup_params = None):
        self.calls.append(("configure", setup_params))
        return self.configure_ok


def actions(package):
    return [action for action, _ in package.calls]


def make_dirs(root, *names):
    for name in names:
        os.makedirs(os.path.join(root, name, "linux"))


def test_packages_are_set_up_in_order(tmp_path):
    first, second = Package("First"), Package("Second")

    assert setup.setup_packages([first, second], "tool", str(tmp_path)) is True
    assert (actions(first), actions(second)) == (["setup"], ["setup"])
    assert isinstance(first.calls[0][1], config.SetupParams)


def test_offline_restores_instead_of_downloading(tmp_path):
    package = Package("Only")

    setup.setup_packages([package], "tool", str(tmp_path), offline = True)

    assert actions(package) == ["setup_offline"]


def test_configure_runs_after_each_setup(tmp_path):
    first, second = Package("First"), Package("Second")
    params = config.SetupParams(verbose = True)

    setup.setup_packages([first, second], "tool", str(tmp_path), configure = True, setup_params = params)

    assert actions(first) == actions(second) == ["setup", "configure"]
    assert {passed for package in (first, second) for _, passed in package.calls} == {params}


def test_a_failed_setup_stops_the_run(tmp_path):
    first, second = Package("First", setup_ok = False), Package("Second")

    assert setup.setup_packages([first, second], "tool", str(tmp_path), configure = True) is False
    assert (actions(first), actions(second)) == (["setup"], [])


def test_a_failed_configure_stops_the_run(tmp_path):
    first, second = Package("First", configure_ok = False), Package("Second")

    assert setup.setup_packages([first, second], "tool", str(tmp_path), configure = True) is False
    assert actions(second) == []


def test_only_the_selected_packages_are_set_up(tmp_path):
    first, second = Package("First"), Package("Second")

    assert setup.setup_packages([first, second], "tool", str(tmp_path), packages = ["Second"]) is True
    assert (actions(first), actions(second)) == ([], ["setup"])


def test_clean_wipes_the_whole_root(tmp_path):
    root = tmp_path / "tools"
    make_dirs(str(root), "First", "Other")

    setup.setup_packages([Package("First")], "tool", str(root), clean = True)

    assert not root.exists()


def test_clean_with_no_root_is_harmless(tmp_path):
    package = Package("First")

    assert setup.setup_packages([package], "tool", str(tmp_path / "missing"), clean = True) is True
    assert actions(package) == ["setup"]


def test_force_wipes_each_program_dir_of_the_selected_package(tmp_path):
    # An emulator package installs its programs under the emulators root, by program name
    make_dirs(str(tmp_path), "DosBoxX", "ScummVM", "Other")
    package = Package("Computer", programs = ["DosBoxX", "ScummVM"])

    assert setup.setup_packages([package], "emulator", str(tmp_path), force = True) is True
    assert sorted(os.listdir(tmp_path)) == ["Other"]
    assert actions(package) == ["setup"]


def test_force_falls_back_to_the_package_name(tmp_path):
    make_dirs(str(tmp_path), "Plain", "Other")

    setup.setup_packages([Package("Plain", programs = [])], "tool", str(tmp_path), force = True)

    assert sorted(os.listdir(tmp_path)) == ["Other"]


def test_force_spares_unselected_packages(tmp_path):
    make_dirs(str(tmp_path), "First", "Second")

    setup.setup_packages(
        [Package("First"), Package("Second")], "tool", str(tmp_path), force = True, packages = ["First"])

    assert sorted(os.listdir(tmp_path)) == ["Second"]


def test_force_with_nothing_installed_still_sets_up(tmp_path):
    package = Package("First")

    assert setup.setup_packages([package], "tool", str(tmp_path), force = True) is True
    assert actions(package) == ["setup"]


@pytest.mark.parametrize("entry,lister,root_getter,package_type", [
    ("setup_tools", "get_tools", "get_tools_root_dir", "tool"),
    ("setup_emulators", "get_emulators", "get_emulators_root_dir", "emulator"),
])
def test_tools_and_emulators_use_their_own_list_and_root(monkeypatch, entry, lister, root_getter, package_type):
    received = {}
    package_list = [Package("One")]
    params = config.SetupParams()

    def setup_packages(**kwargs):
        received.update(kwargs)
        return True

    monkeypatch.setattr(setup.programs, lister, lambda: package_list)
    monkeypatch.setattr(setup.environment, root_getter, lambda: "/root/" + package_type)
    monkeypatch.setattr(setup, "setup_packages", setup_packages)

    assert getattr(setup, entry)(
        offline = True, configure = True, clean = True, force = True, packages = ["One"], setup_params = params) is True
    assert received == {
        "package_list": package_list, "package_type": package_type, "root_dir": "/root/" + package_type,
        "offline": True, "configure": True, "clean": True, "force": True, "packages": ["One"],
        "setup_params": params}


###########################################################
# Assets
#
# Each pegasus asset directory is a symlink to the matching locker directory,
# which is created first when missing.
###########################################################

def asset_path(root, *levels):
    return os.path.join(str(root), *[str(level) for level in levels])


@pytest.fixture
def asset_dirs(monkeypatch, tmp_path):
    locker = tmp_path / "locker"
    pegasus = tmp_path / "pegasus"
    monkeypatch.setattr(setup.environment, "get_locker_gaming_asset_dir",
        lambda *levels: asset_path(locker, *levels))
    monkeypatch.setattr(setup.environment, "get_game_pegasus_metadata_asset_dir",
        lambda *levels: asset_path(pegasus, *levels))
    return locker, pegasus


def every_asset_dir():
    for category in config.Category.members():
        for subcategory in config.subcategory_map[category]:
            for asset_type in config.AssetType.members():
                yield category, subcategory, asset_type


def test_assets_link_every_pegasus_dir_to_the_locker(asset_dirs, monkeypatch):
    locker, pegasus = asset_dirs
    links = []

    def create_symlink(src, dest, cwd, **kwargs):
        links.append((src, dest, cwd))
        return True

    monkeypatch.setattr(setup.fileops, "create_symlink", create_symlink)

    assert setup.setup_assets() is True

    expected = list(every_asset_dir())
    assert len(links) == len(expected)
    category, subcategory, asset_type = expected[0]
    assert links[0] == (
        asset_path(locker, category, subcategory, asset_type),
        asset_path(pegasus, category, subcategory, asset_type),
        asset_path(pegasus, category, subcategory))
    assert os.path.isdir(asset_path(locker, category, subcategory, asset_type))


def test_assets_keep_an_existing_locker_dir(asset_dirs, monkeypatch):
    locker, _ = asset_dirs
    category, subcategory, asset_type = next(every_asset_dir())
    existing = asset_path(locker, category, subcategory, asset_type)
    os.makedirs(existing)
    keep = os.path.join(existing, "keep.png")
    open(keep, "w").close()
    made = []

    monkeypatch.setattr(setup.fileops, "create_symlink", lambda **kwargs: True)
    monkeypatch.setattr(setup.fileops, "make_directory", lambda src, **kwargs: made.append(src))

    setup.setup_assets()

    assert existing not in made
    assert os.path.exists(keep)


def test_assets_stop_at_the_first_failed_link(asset_dirs, monkeypatch):
    links = []

    def create_symlink(**kwargs):
        links.append(kwargs)
        return False

    monkeypatch.setattr(setup.fileops, "create_symlink", create_symlink)

    assert setup.setup_assets(verbose = True, pretend_run = True, exit_on_failure = True) is False
    assert len(links) == 1
    assert (links[0]["verbose"], links[0]["pretend_run"], links[0]["exit_on_failure"]) == (True, True, True)
