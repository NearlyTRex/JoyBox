# Imports
import os

# Local imports
import joybox.bootstrap.installers as installers
from joybox import environment
from fakes import RecordingConnection


###########################################################
# joybox in the venv
#
# The commands and every import come from an editable install of this checkout,
# so installed means pip reports joybox as editable from exactly this checkout.
###########################################################

def repo_dir():
    return os.path.normpath(environment.get_repo_root(expand = True))


def build(pip_show = ""):
    connection = RecordingConnection(command_output = {"show joybox": pip_show})
    python = installers.Python(connection)
    python.get_packages = lambda: []
    return python, connection


def show_output(location):
    return "Name: joybox\nVersion: 0.1.0\nEditable project location: %s\n" % location


def test_install_installs_this_checkout_editable(isolated_settings):
    python, connection = build()
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))
    python.install()

    assert any(
        command[1:] == ["install", "--editable", repo_dir() + "[dev,decompiler]"]
        for command in connection.commands)


def test_not_installed_is_not_installed(isolated_settings):
    python, _ = build()
    assert not python.is_installed()


def test_another_checkout_is_not_installed(isolated_settings):
    python, _ = build(show_output("/elsewhere/JoyBox"))
    assert not python.is_installed()


def test_this_checkout_is_installed(isolated_settings):
    python, _ = build(show_output(repo_dir()))
    assert python.is_installed()


def test_uninstall_removes_joybox(isolated_settings):
    python, connection = build()
    python.uninstall()

    assert any(command[1:] == ["uninstall", "-y", "joybox"] for command in connection.commands)
