# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Installed state
#
# The package enables cockpit.socket by itself, so installed also needs the
# loopback binding and the nginx site that fronts it.
###########################################################

LISTEN_OVERRIDE = "/etc/systemd/system/cockpit.socket.d/joybox-listen.conf"
NGINX_SITE = "/etc/nginx/sites-enabled/cockpit.conf"


def build(existing):
    connection = RecordingConnection(
        existing_paths = existing,
        command_output = {"is-enabled cockpit.socket": "enabled"})
    return installers.Cockpit(connection)


def test_the_package_alone_is_not_installed(isolated_settings):
    assert not build([]).is_installed()


def test_a_public_socket_is_not_installed(isolated_settings):
    assert not build([NGINX_SITE]).is_installed()


def test_a_missing_nginx_site_is_not_installed(isolated_settings):
    assert not build([LISTEN_OVERRIDE]).is_installed()


def test_loopback_and_nginx_site_is_installed(isolated_settings):
    assert build([LISTEN_OVERRIDE, NGINX_SITE]).is_installed()


def test_nginx_proxies_to_loopback(isolated_settings):
    from joybox.bootstrap.installers import installer_cockpit
    assert "proxy_pass https://127.0.0.1:" in installer_cockpit.nginx_config_template


def test_only_remote_ubuntu_is_supported(isolated_settings):
    assert build([]).get_supported_environments() == [constants.EnvironmentType.REMOTE_UBUNTU]


def test_install_fronts_cockpit_with_nginx(isolated_settings):
    cockpit = build([])
    connection = cockpit.connection

    assert cockpit.install()
    assert connection.ran(cockpit.cockpit_manager_tool, "install")
    assert connection.ran(cockpit.nginx_manager_tool, "install_conf /tmp/cockpit.conf")
    assert connection.ran(cockpit.nginx_manager_tool, "link_conf cockpit.conf")
    assert connection.ran(cockpit.nginx_manager_tool, "systemctl restart")
    assert "/tmp/cockpit.conf" in connection.removed_paths


def test_an_unwritable_site_is_not_installed(isolated_settings, monkeypatch):
    cockpit = build([])
    monkeypatch.setattr(cockpit.connection, "write_file", lambda src, contents, sudo = False: False)

    assert cockpit.install()
    assert not cockpit.connection.ran("install_conf")


def test_uninstall_removes_the_site_then_cockpit(isolated_settings):
    cockpit = build([NGINX_SITE, LISTEN_OVERRIDE])
    connection = cockpit.connection

    assert cockpit.uninstall()
    assert connection.command_strings() == [
        f"{cockpit.nginx_manager_tool} remove_conf cockpit.conf",
        f"{cockpit.nginx_manager_tool} systemctl restart",
        f"{cockpit.cockpit_manager_tool} uninstall"]
