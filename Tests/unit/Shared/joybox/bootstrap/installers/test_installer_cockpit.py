# Imports
import pytest

# Local imports
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
