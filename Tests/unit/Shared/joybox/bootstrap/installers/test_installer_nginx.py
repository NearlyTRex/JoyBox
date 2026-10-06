# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_nginx
from fakes import RecordingConnection


###########################################################
# Nginx
#
# Owns the default server and the static apex fallback; every file reaches
# /etc/nginx through the manager script the account's sudo grant covers.
###########################################################

class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None):
    connection = connection if connection is not None else RecordingConnection()
    return installers.Nginx(connection), connection


def test_only_remote_ubuntu_is_supported(isolated_settings):
    nginx, _ = make()
    assert nginx.get_supported_environments() == [constants.EnvironmentType.REMOTE_UBUNTU]


def test_installed_follows_the_binary(isolated_settings):
    nginx, connection = make()
    assert not nginx.is_installed()

    connection.existing_paths.add("/usr/sbin/nginx")
    assert nginx.is_installed()


def test_install_writes_the_default_entry_snippet_and_page(isolated_settings):
    nginx, connection = make()

    assert nginx.install()
    assert "server_name joybox.test;" in connection.written("/tmp/default")
    assert connection.ran(nginx.nginx_manager_tool, "install_conf /tmp/default")
    assert connection.ran(nginx.nginx_manager_tool, "link_conf default")
    assert connection.written("/tmp/apex-root.conf") == installer_nginx.apex_root_snippet_template
    assert connection.ran(nginx.nginx_manager_tool, "install_snippet /tmp/apex-root.conf")
    assert connection.written("/tmp/index.html") == installer_nginx.apex_fallback_page
    assert connection.ran(nginx.nginx_manager_tool, "copy_html /tmp/index.html")
    assert connection.ran(nginx.nginx_manager_tool, "systemctl restart")
    assert {"/tmp/default", "/tmp/apex-root.conf", "/tmp/index.html"} <= set(connection.removed_paths)


def test_unwritable_files_are_not_installed(isolated_settings):
    nginx, connection = make(UnwritableConnection())

    assert nginx.install()
    assert not connection.ran("install_conf")
    assert not connection.ran("install_snippet")
    assert not connection.ran("copy_html")
    assert connection.ran(nginx.nginx_manager_tool, "systemctl restart")


def test_uninstall_stops_and_removes(isolated_settings):
    nginx, connection = make()

    assert nginx.uninstall()
    assert connection.ran(nginx.nginx_manager_tool, "systemctl stop")
    assert connection.ran(nginx.nginx_manager_tool, "remove_conf default")
    assert connection.ran("remove -y nginx")
    assert connection.ran("remove -y nginx-common")
