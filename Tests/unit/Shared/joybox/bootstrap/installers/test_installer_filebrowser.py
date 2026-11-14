# Imports
import base64

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_filebrowser


###########################################################
# FileBrowser
###########################################################

SECRET = base64.b64encode(bytes(range(16))).decode()


@pytest.fixture
def admin(isolated_settings):
    isolated_settings.set_value("UserData.FileBrowser", "filebrowser_admin_user", "pam@home")
    isolated_settings.set_value("UserData.FileBrowser", "filebrowser_admin_pass", "x" * installer_filebrowser.MINIMUM_ADMIN_PASS_LENGTH)
    isolated_settings.set_value("UserData.FileBrowser", "filebrowser_totp_secret", SECRET)
    return isolated_settings


def test_the_rate_limit_burst_is_rendered(docker_app):
    nginx = docker_app(installers.FileBrowser).nginx()

    assert "limit_req zone=mylimit burst=100 nodelay;" in nginx
    assert "server_name cloud.joybox.test;" in nginx
    assert "proxy_pass http://localhost:8082;" in nginx


def test_uploads_are_not_size_limited(docker_app):
    assert "client_max_body_size 0;" in docker_app(installers.FileBrowser).nginx()


def test_the_env_carries_the_root_and_pinned_image(admin, docker_app):
    env = docker_app(installers.FileBrowser).env()

    assert "FILEBROWSER_ROOT=/mnt/storage" in env
    assert "FILEBROWSER_PORT_HTTP=8082" in env
    assert "FILEBROWSER_ADMIN_USER='pam@home'" in env
    assert "FILEBROWSER_IMAGE=gtstef/filebrowser:" in env


def test_a_password_at_the_minimum_length_is_accepted(admin, docker_app):
    assert docker_app(installers.FileBrowser).installer.check_required_settings()


def test_a_missing_root_fails_before_the_admin_checks(admin, docker_app, caplog):
    admin.set_value("UserData.FileBrowser", "filebrowser_user_root", "")

    assert not docker_app(installers.FileBrowser).installer.check_required_settings()
    assert "user_root" in caplog.text


def test_a_quote_in_the_password_is_refused(admin, docker_app):
    admin.set_value("UserData.FileBrowser", "filebrowser_admin_pass", "it's twelve chars")

    assert not docker_app(installers.FileBrowser).installer.check_required_settings()


def test_a_value_that_is_not_text_is_not_a_secret():
    assert not installer_filebrowser.is_totp_secret(None)


def test_only_the_data_volume_is_backed_up(docker_app):
    assert docker_app(installers.FileBrowser).installer.backup_volumes == ["data"]


def test_install_with_bad_settings_writes_nothing(docker_app):
    app = docker_app(installers.FileBrowser)

    assert not app.installer.install()
    assert app.connection.write_log == []
