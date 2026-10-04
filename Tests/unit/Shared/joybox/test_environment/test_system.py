# Imports
import os
import pytest

# Local imports
from joybox import environment


###########################################################
# Editor
#
# The ini wins, then $EDITOR, then $VISUAL, then a per-platform default.
###########################################################

@pytest.fixture
def editor_env(isolated_settings, monkeypatch):
    monkeypatch.delenv("EDITOR", raising = False)
    monkeypatch.delenv("VISUAL", raising = False)
    isolated_settings.set_value("Tools.System", "editor", "")
    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: False)
    return isolated_settings


def test_the_ini_editor_wins(editor_env, monkeypatch):
    editor_env.set_value("Tools.System", "editor", "kate")
    monkeypatch.setenv("EDITOR", "vim")

    assert environment.get_editor() == "kate"


def test_editor_beats_visual(editor_env, monkeypatch):
    monkeypatch.setenv("EDITOR", "vim")
    monkeypatch.setenv("VISUAL", "code")

    assert environment.get_editor() == "vim"


def test_visual_is_the_last_variable_tried(editor_env, monkeypatch):
    monkeypatch.setenv("VISUAL", "code")

    assert environment.get_editor() == "code"


@pytest.mark.parametrize("is_windows,editor", [(False, "nano"), (True, "notepad.exe")])
def test_the_fallback_editor_follows_the_platform(editor_env, monkeypatch, is_windows, editor):
    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: is_windows)

    assert environment.get_editor() == editor


###########################################################
# Symlinks
#
# Unix always has them; Windows is probed with a real link in the home dir,
# which is left in place so later probes are free.
###########################################################

def test_unix_supports_symlinks(monkeypatch):
    monkeypatch.setattr(environment.platform_info, "is_unix_platform", lambda: True)

    assert environment.are_symlinks_supported() is True


@pytest.fixture
def windows_home(monkeypatch, tmp_path):
    from joybox import fileops

    created = []

    def create_symlink(src, dest, **kwargs):
        created.append(dest)
        os.symlink(src, dest)
        return True

    monkeypatch.setattr(environment.platform_info, "is_unix_platform", lambda: False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(fileops, "touch_file", lambda src, **kwargs: open(src, "w").close() or True)
    monkeypatch.setattr(fileops, "create_symlink", create_symlink)
    return {"home": tmp_path, "created": created}


def test_windows_probes_with_a_link_in_the_home_dir(windows_home):
    assert environment.are_symlinks_supported() is True
    assert windows_home["created"] == [str(windows_home["home"] / ".symdest")]


def test_an_existing_probe_link_is_reused(windows_home):
    os.symlink(windows_home["home"] / ".symsrc", windows_home["home"] / ".symdest")

    assert environment.are_symlinks_supported() is True
    assert windows_home["created"] == []


def test_windows_without_link_rights_is_unsupported(windows_home, monkeypatch):
    from joybox import fileops

    monkeypatch.setattr(fileops, "create_symlink", lambda src, dest, **kwargs: False)

    assert environment.are_symlinks_supported() is False


###########################################################
# Repo root
#
# The repo root is the scripts dir's parent, kept unexpanded unless asked.
###########################################################

@pytest.mark.parametrize("scripts_dir,root", [
    ("$HOME/Repositories/JoyBox/Scripts", "$HOME/Repositories/JoyBox"),
    ("/srv/JoyBox/Scripts/", "/srv/JoyBox"),
    ("C:\\Repositories\\JoyBox\\Scripts", "C:\\Repositories\\JoyBox"),
    ("/data/Scripts/JoyBox/Scripts", "/data/Scripts/JoyBox"),
    ("/data/ScriptsArchive/JoyBox/Scripts", "/data/ScriptsArchive/JoyBox"),
])
def test_the_repo_root_is_the_scripts_parent(isolated_settings, scripts_dir, root):
    isolated_settings.set_value("UserData.Dirs", "scripts_dir", scripts_dir)

    assert environment.get_repo_root() == root


def test_the_repo_root_has_a_default(isolated_settings):
    isolated_settings.set_value("UserData.Dirs", "scripts_dir", "")

    assert environment.get_repo_root() == "$HOME/Repositories/JoyBox"


def test_the_repo_root_can_be_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("HOME", "/home/someone")
    isolated_settings.set_value("UserData.Dirs", "scripts_dir", "$HOME/Repositories/JoyBox/Scripts")

    assert environment.get_repo_root(expand = True) == "/home/someone/Repositories/JoyBox"


###########################################################
# Scripts
###########################################################

def test_the_scripts_icons_dir_sits_under_the_scripts_root():
    assert environment.get_scripts_icons_dir().startswith(environment.get_scripts_root_dir())


###########################################################
# Commands
#
# pip installs each command into the venv, so that is where one is run from.
###########################################################

def test_commands_live_in_the_venv(monkeypatch):
    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: False)
    venv_dir = environment.settings.get_path_value("Tools.Python", "python_venv_dir")

    assert environment.get_command_path("backup_tool") == os.path.join(venv_dir, "bin", "backup_tool")


def test_windows_commands_are_executables_in_scripts(monkeypatch):
    monkeypatch.setattr(environment.platform_info, "is_windows_platform", lambda: True)
    venv_dir = environment.settings.get_path_value("Tools.Python", "python_venv_dir")

    assert environment.get_command_path("backup_tool") == os.path.join(venv_dir, "Scripts", "backup_tool.exe")


###########################################################
# Roots from settings
###########################################################

@pytest.mark.parametrize("accessor,field", [
    ("get_repositories_root_dir", "repositories_dir"),
    ("get_cache_root_dir", "cache_dir"),
    ("get_game_metadata_root_dir", "game_metadata_dir"),
    ("get_file_metadata_root_dir", "file_metadata_dir"),
])
def test_each_user_data_root_comes_from_settings(isolated_settings, accessor, field):
    isolated_settings.set_value("UserData.Dirs", field, "/joybox-test/" + field)

    assert getattr(environment, accessor)() == "/joybox-test/" + field


@pytest.mark.parametrize("accessor,leaf", [
    ("get_cache_sync_dir", "Sync"),
    ("get_cache_purchases_dir", "Purchases"),
])
def test_each_cache_area_sits_under_the_cache_root(monkeypatch, accessor, leaf):
    monkeypatch.setattr(environment, "get_cache_root_dir", lambda: "/cache")

    assert getattr(environment, accessor)() == os.path.join("/cache", leaf)
