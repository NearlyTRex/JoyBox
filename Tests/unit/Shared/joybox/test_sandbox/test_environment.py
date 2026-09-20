# Imports
import getpass
import os
import pytest

# Local imports
from joybox import commandoptions, config, sandbox
from sandbox_helpers import options, WINE, SANDBOXIE, NEITHER, PREFIX


###########################################################
# Prefix environment
#
# Everything a wine command needs in its environment before it runs. A missing
# variable sends the game to the default prefix, where its saves are invisible
# to the collection.
###########################################################

def prefixed(wine = True, **kwargs):
    entry = options(wine = wine, sandboxie = not wine, **kwargs)
    entry.set_prefix_name("game")
    return entry


def env_of(built_options):
    return built_options.get_env() or {}


def setup_env(entry, cmd = None):
    return sandbox.setup_prefix_environment(cmd or ["game.exe"], options = entry)


def test_a_non_prefix_command_is_left_alone():
    entry = NEITHER()
    cmd, built = sandbox.setup_prefix_environment(["game.exe"], options = entry)

    assert cmd == ["game.exe"]
    assert built is entry


def test_a_prefix_command_gets_a_copy_of_its_options():
    # The caller's options are reused for the next launch.
    entry = prefixed()
    cmd, built = setup_env(entry)

    assert built is not entry


def test_wine_debug_output_is_silenced():
    cmd, built = setup_env(prefixed())

    assert env_of(built).get("WINEDEBUG") == "-all"


def test_the_prefix_location_is_exported():
    # Without this wine uses ~/.wine and the saves land outside the collection.
    entry = prefixed()
    entry.set_prefix_dir("/prefixes/game")
    cmd, built = setup_env(entry)

    assert env_of(built).get("WINEPREFIX") == "/prefixes/game"


def test_no_prefix_directory_exports_no_location():
    cmd, built = setup_env(prefixed(prefix_dir = None))

    assert "WINEPREFIX" not in env_of(built)


def test_a_64_bit_prefix_is_the_default():
    cmd, built = setup_env(prefixed())

    assert env_of(built).get("WINEARCH") == "win64"


def test_a_32_bit_prefix_is_declared():
    # A prefix created with the wrong bitness cannot be changed afterwards.
    entry = prefixed()
    entry.set_is_32_bit(True)
    cmd, built = setup_env(entry)

    assert env_of(built).get("WINEARCH") == "win32"


def test_the_menu_builder_is_always_disabled():
    # Otherwise every install litters the host's application menu.
    cmd, built = setup_env(prefixed())

    assert "winemenubuilder.exe=d" in env_of(built).get("WINEDLLOVERRIDES", "")


def test_game_overrides_are_appended():
    entry = prefixed()
    entry.set_overrides(["ddraw=n,b"])
    cmd, built = setup_env(entry)
    overrides = env_of(built).get("WINEDLLOVERRIDES", "")

    assert "winemenubuilder.exe=d" in overrides
    assert "ddraw=n,b" in overrides


def test_overrides_are_semicolon_separated():
    entry = prefixed()
    entry.set_overrides(["ddraw=n,b", "d3d9=n"])
    cmd, built = setup_env(entry)

    assert env_of(built).get("WINEDLLOVERRIDES", "").count(";") == 2


def test_wine_blocks_on_its_own_processes():
    cmd, built = setup_env(prefixed())

    assert built.get_blocking_processes()


def test_a_sandboxie_command_blocks_on_its_own_processes():
    cmd, built = setup_env(prefixed(wine = False))

    assert built.get_blocking_processes()


def test_a_sandboxie_command_gets_no_wine_environment():
    cmd, built = setup_env(prefixed(wine = False))

    assert "WINEPREFIX" not in env_of(built)
    assert "WINEARCH" not in env_of(built)


def test_the_command_itself_is_unchanged_by_the_environment():
    cmd, built = setup_env(prefixed(), cmd = ["game.exe", "-windowed"])

    assert cmd == ["game.exe", "-windowed"]


def test_setting_up_twice_does_not_duplicate_overrides():
    entry = prefixed()
    cmd, once = setup_env(entry)
    cmd, twice = sandbox.setup_prefix_environment(cmd, options = once)

    assert twice.get_env()["WINEDLLOVERRIDES"].count("winemenubuilder.exe=d") == 1


###########################################################
# Installing libraries into a prefix
###########################################################

@pytest.fixture
def prefix_tree(tmp_path):
    root = tmp_path / "prefix"
    for relative in ["drive_c/windows/system32", "drive_c/windows/syswow64"]:
        (root / relative).mkdir(parents = True)
    libs = tmp_path / "libs"
    libs.mkdir()
    (libs / "lib32.dll").write_text("32 bit")
    (libs / "lib64.dll").write_text("64 bit")
    return root, libs


def test_a_64_bit_prefix_takes_both_architectures(prefix_tree):
    # 64 bit wine keeps 32 bit libraries in syswow64, not system32.
    root, libs = prefix_tree
    entry = options(wine = True, prefix_dir = str(root))
    sandbox.install_wine_dlls(
        entry, dlls_32 = [str(libs / "lib32.dll")], dlls_64 = [str(libs / "lib64.dll")])

    assert (root / "drive_c" / "windows" / "system32" / "lib64.dll").exists()
    assert (root / "drive_c" / "windows" / "syswow64" / "lib32.dll").exists()


def test_a_32_bit_prefix_takes_only_the_32_bit_libraries(prefix_tree):
    root, libs = prefix_tree
    entry = options(wine = True, prefix_dir = str(root))
    entry.set_is_32_bit(True)
    sandbox.install_wine_dlls(
        entry, dlls_32 = [str(libs / "lib32.dll")], dlls_64 = [str(libs / "lib64.dll")])

    assert (root / "drive_c" / "windows" / "system32" / "lib32.dll").exists()
    assert not (root / "drive_c" / "windows" / "system32" / "lib64.dll").exists()


def test_a_32_bit_prefix_has_no_syswow64_copies(prefix_tree):
    root, libs = prefix_tree
    entry = options(wine = True, prefix_dir = str(root))
    entry.set_is_32_bit(True)
    sandbox.install_wine_dlls(entry, dlls_32 = [str(libs / "lib32.dll")])

    assert not (root / "drive_c" / "windows" / "syswow64" / "lib32.dll").exists()


def test_no_libraries_installs_nothing(prefix_tree):
    root, libs = prefix_tree
    entry = options(wine = True, prefix_dir = str(root))
    sandbox.install_wine_dlls(entry)

    assert os.listdir(str(root / "drive_c" / "windows" / "system32")) == []


def test_installing_dispatches_on_the_prefix_kind(prefix_tree, monkeypatch):
    root, libs = prefix_tree
    reached = []
    monkeypatch.setattr(
        sandbox, "install_wine_dlls", lambda *args, **kwargs: reached.append("wine"))
    monkeypatch.setattr(
        sandbox, "install_sandboxie_dlls",
        lambda *args, **kwargs: reached.append("sandboxie"))

    sandbox.install_dlls(options(wine = True, prefix_dir = str(root)))
    sandbox.install_dlls(options(sandboxie = True, prefix_dir = str(root)))

    assert reached == ["wine", "sandboxie"]


def test_a_non_prefix_installs_nothing(prefix_tree, monkeypatch):
    root, libs = prefix_tree

    def fail(*args, **kwargs):
        raise AssertionError("nothing should be installed")

    monkeypatch.setattr(sandbox, "install_wine_dlls", fail)
    monkeypatch.setattr(sandbox, "install_sandboxie_dlls", fail)
    sandbox.install_dlls(NEITHER())
