# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
from joybox.bootstrap.installers import installer
from joybox import runoptions
from joybox.connection import ConnectionLocal, ConnectionSSH
from fakes import RecordingConnection


###########################################################
# Installer base
###########################################################

REMOTE_HOME = "/home/deploy"


def build():
    connection = RecordingConnection(command_output = {"printf": REMOTE_HOME})
    base = installer.Installer(connection, runoptions.RunFlags(verbose = False))
    return base, connection


###########################################################
# Package descriptors
###########################################################

def test_string_package_is_its_own_id_and_name():
    assert installer.get_package_id("vim") == "vim"
    assert installer.get_package_info("vim") == {
        "id": "vim", "name": "vim", "description": "", "category": ""}


def test_dict_package_fields():
    pkg = {"id": "vim", "name": "Vim", "description": "editor", "category": "dev"}
    assert installer.get_package_id(pkg) == "vim"
    assert installer.get_package_info(pkg) == pkg


def test_dict_package_name_defaults_to_id():
    assert installer.get_package_id({}) == ""
    assert installer.get_package_info({"id": "vim"})["name"] == "vim"


###########################################################
# Remote home
###########################################################

def test_the_remote_home_is_resolved():
    base, _ = build()
    assert base.get_remote_home() == REMOTE_HOME


def test_the_remote_home_is_resolved_once():
    # Every app directory lookup would otherwise cost a round trip.
    base, connection = build()
    base.get_remote_home()
    base.get_remote_home()

    assert len([c for c in connection.command_strings() if "printf" in c]) == 1


def test_an_unresolvable_home_falls_back():
    connection = RecordingConnection(command_output = {"printf": ""})
    base = installer.Installer(connection, runoptions.RunFlags(verbose = False))

    assert base.get_remote_home() == "$HOME"


###########################################################
# Environment support
###########################################################

def test_every_environment_is_supported_by_default():
    base, _ = build()
    unsupported = [environment for environment in constants.EnvironmentType if base.supports_environment(environment) is not True]

    assert not unsupported, unsupported


def test_an_unsupported_environment_is_rejected():
    base, _ = build()
    base.get_supported_environments = lambda: [constants.EnvironmentType.REMOTE_UBUNTU]

    assert base.supports_environment(constants.EnvironmentType.REMOTE_UBUNTU) is True
    assert base.supports_environment(constants.EnvironmentType.LOCAL_WINDOWS) is False


###########################################################
# Nginx snippets
###########################################################

def test_a_snippet_is_staged_installed_and_cleaned_up():
    base, connection = build()
    assert base.install_nginx_snippet("apex-root.conf", "location / { return 404; }")

    assert connection.written("/tmp/apex-root.conf") == "location / { return 404; }"
    assert connection.ran("install_snippet", "/tmp/apex-root.conf")
    assert "/tmp/apex-root.conf" in connection.removed_paths


def test_a_snippet_that_cannot_be_staged_fails():
    base, connection = build()
    connection.write_file = lambda src, contents, sudo = False: False

    assert base.install_nginx_snippet("apex-root.conf", "location / { return 404; }") is False
    assert not connection.ran("install_snippet")


def test_a_site_config_is_staged_installed_and_linked():
    base, connection = build()
    assert base.install_nginx_conf("site.conf", "server {}")

    assert connection.written("/tmp/site.conf") == "server {}"
    assert connection.ran("install_conf", "/tmp/site.conf")
    assert connection.ran("link_conf", "site.conf")
    assert "/tmp/site.conf" in connection.removed_paths


def test_a_site_config_that_cannot_be_staged_fails():
    base, connection = build()
    connection.write_file = lambda src, contents, sudo = False: False

    assert base.install_nginx_conf("site.conf", "server {}") is False
    assert not connection.ran("install_conf")
    assert not connection.ran("link_conf")


###########################################################
# Target locality
###########################################################

def test_a_local_target_is_not_remote():
    local = ConnectionLocal(flags = runoptions.RunFlags(verbose = False))
    assert installer.Installer(local, runoptions.RunFlags(verbose = False)).is_remote_target() is False


def test_an_ssh_target_is_remote():
    ssh = ConnectionSSH(ssh_host = "server.example", flags = runoptions.RunFlags(verbose = False))
    assert installer.Installer(ssh, runoptions.RunFlags(verbose = False)).is_remote_target() is True


###########################################################
# Abstract defaults
###########################################################

def test_the_base_reports_nothing_installed():
    base, _ = build()

    assert base.is_installed() is False
    assert base.get_package_status() is None


def test_the_base_does_not_claim_a_successful_action():
    # A subclass that forgets to override must not report success.
    base, _ = build()

    assert base.install() is False
    assert base.uninstall() is False


def test_the_base_backup_and_restore_are_harmless():
    base, connection = build()

    assert base.backup() is True
    assert base.restore() is True
    assert connection.calls == []


###########################################################
# Environment type
###########################################################

def test_supported_environment_defaults_to_the_configured_type(isolated_settings):
    base, _ = build()
    base.get_supported_environments = lambda: [constants.EnvironmentType.LOCAL_UBUNTU]

    base.set_environment_type(constants.EnvironmentType.LOCAL_UBUNTU)
    assert base.get_environment_type() == constants.EnvironmentType.LOCAL_UBUNTU
    assert base.supports_environment() is True

    base.set_environment_type(constants.EnvironmentType.REMOTE_UBUNTU)
    assert base.supports_environment() is False


def test_windows_resolves_winget_instead_of_apt(isolated_settings, monkeypatch):
    monkeypatch.setattr(installer.platform_info, "is_windows_platform", lambda: True)
    isolated_settings.set_value("Tools.WinGet", "winget_exe", "winget.exe")
    isolated_settings.set_value("Tools.WinGet", "winget_install_dir", "C:/WindowsApps")
    base = installer.Installer(RecordingConnection(), runoptions.RunFlags(verbose = False))

    assert base.winget_tool == os.path.join("C:/WindowsApps", "winget.exe")
    assert not hasattr(base, "aptget_tool")


###########################################################
# Upstream install scripts
###########################################################

def test_an_install_script_is_run_and_removed():
    base, connection = build()

    assert base.install_from_script("https://example.test/install.sh", "x_install.sh", runner = "bash") is True
    assert connection.downloads == [("https://example.test/install.sh", "/tmp/x_install.sh")]
    assert connection.ran("bash /tmp/x_install.sh")
    assert connection.removed_paths == ["/tmp/x_install.sh"]


def test_a_failed_install_script_is_removed_and_reported():
    connection = RecordingConnection(return_codes = {"x_install.sh": 3})
    base = installer.Installer(connection, runoptions.RunFlags(verbose = False))

    assert base.install_from_script("https://example.test/install.sh", "x_install.sh") is False
    assert connection.ran("sh /tmp/x_install.sh")
    assert connection.removed_paths == ["/tmp/x_install.sh"]


def test_an_install_script_gets_its_arguments():
    base, connection = build()

    assert base.install_from_script("https://example.test/install.sh", "x_install.sh", args = ["-y"]) is True
    assert connection.ran("sh /tmp/x_install.sh -y")
