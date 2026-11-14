# Imports
import json

# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_dockerapp
from joybox.bootstrap.installers import installer_navidrome


###########################################################
# Navidrome
###########################################################

def test_the_env_carries_the_port_library_and_pinned_image(docker_app):
    env = docker_app(installers.Navidrome).env()

    assert "NAVIDROME_PORT_HTTP=8085" in env
    assert "NAVIDROME_MUSIC_DIR=/mnt/storage/Music" in env
    assert "NAVIDROME_IMAGE=deluan/navidrome:" in env


def test_the_music_is_mounted_read_only():
    assert "${NAVIDROME_MUSIC_DIR}:/music:ro" in installer_navidrome.docker_compose_template


def test_the_site_is_a_plain_http_proxy(docker_app):
    app = docker_app(installers.Navidrome)

    assert app.installer.nginx_config_template == installer_dockerapp.nginx_http_config_template
    assert "music.joybox.test" in app.nginx()
    assert "proxy_pass http://localhost:8085" in app.nginx()


def test_a_missing_music_dir_fails_the_settings_check(isolated_settings, docker_app):
    isolated_settings.set_value("UserData.Navidrome", "navidrome_music_dir", "")

    assert not docker_app(installers.Navidrome).installer.check_required_settings()


def test_only_the_config_volume_is_backed_up(docker_app):
    assert docker_app(installers.Navidrome).installer.backup_volumes == ["config_data"]


def test_the_admin_is_sent_through_a_private_payload(isolated_settings, docker_app):
    isolated_settings.set_value("UserData.Navidrome", "navidrome_admin_user", "pam")
    isolated_settings.set_value("UserData.Navidrome", "navidrome_admin_pass", "secret")
    app = docker_app(installers.Navidrome, command_output = {"-X POST": "200"})

    assert app.installer.post_install()
    assert app.connection.ran("sh -c", "http://127.0.0.1:8085/app/")
    assert json.loads(app.connection.written(".api-payload.json")) == {"username": "pam", "password": "secret"}
    assert app.connection.ran("-X POST", "http://127.0.0.1:8085/auth/createAdmin")
