# Local imports
import joybox.bootstrap as bootstrap
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_nginx
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# Wordpress
#
# WordPress serves the apex, so it takes over the apex-root snippet rather
# than adding a second server block, and hands it back on uninstall.
###########################################################

REMOTE_HOME = "/home/deploy"
APP_DIR = f"{REMOTE_HOME}/apps/wordpress"


class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


def make(connection = None, **kwargs):
    if connection is None:
        connection = RecordingConnection(command_output = {"printf": REMOTE_HOME}, **kwargs)
    return installers.Wordpress(connection, runoptions.RunFlags(verbose = False)), connection


def test_install_proxies_the_apex_and_redirects_www(isolated_settings):
    wordpress, connection = make()

    assert wordpress.install_nginx_config()
    assert f"proxy_pass http://localhost:{wordpress.nginx_config_values['port_http']};" in \
        connection.written("/tmp/apex-root.conf")
    assert connection.ran(wordpress.nginx_manager_tool, "install_snippet /tmp/apex-root.conf")
    assert connection.written("/tmp/wordpress.conf")
    assert connection.ran(wordpress.nginx_manager_tool, "install_conf /tmp/wordpress.conf")
    assert connection.ran(wordpress.nginx_manager_tool, "link_conf wordpress.conf")


def test_an_unwritable_redirect_is_not_installed(isolated_settings):
    wordpress, connection = make(UnwritableConnection(command_output = {"printf": REMOTE_HOME}))

    assert wordpress.install_nginx_config()
    assert not connection.ran("install_conf")


def test_uninstall_hands_the_apex_back_to_the_static_fallback(isolated_settings):
    wordpress, connection = make()

    assert wordpress.uninstall_nginx_config()
    assert connection.written("/tmp/apex-root.conf") == installer_nginx.apex_root_snippet_template
    assert connection.ran(wordpress.nginx_manager_tool, "remove_conf wordpress.conf")


###########################################################
# Seeding
###########################################################

def test_seeding_can_be_turned_off(isolated_settings):
    isolated_settings.set_value("UserData.Wordpress", "wordpress_seed_enabled", "no")
    wordpress, connection = make()

    assert wordpress.post_install()
    assert connection.commands == []


def test_an_unhealthy_site_is_not_seeded(isolated_settings):
    wordpress, connection = make(return_codes = {"sh -c": 1})

    assert not wordpress.post_install()
    assert not connection.ran("/seed/seed.sh")


def test_the_seed_ships_from_the_repo_and_runs_in_wpcli(isolated_settings):
    wordpress, connection = make()

    assert wordpress.post_install()
    assert connection.called("transfer_files")[0][1] == (
        f"{bootstrap.get_data_dir()}/wordpress", f"{APP_DIR}/seed")
    assert (f"{APP_DIR}/seed", "a+rX") in connection.permissions
    assert connection.ran("compose --env-file", f"{APP_DIR}/.env",
        "run --rm --entrypoint /bin/sh wpcli /seed/seed.sh")
    assert [call[1][0] for call in connection.called("set_current_working_directory")] == [APP_DIR, None]


def test_a_failed_seed_fails_the_post_install(isolated_settings):
    wordpress, connection = make(return_codes = {"seed.sh": 1})

    assert not wordpress.post_install()
    assert connection.called("set_current_working_directory")[-1][1] == (None,)
