# Imports
import json

# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_audiobookshelf
from joybox.bootstrap.installers import installer_dockerapp


###########################################################
# Audiobookshelf
###########################################################

NEW_SERVER = '{"app": "audiobookshelf", "isInit": false}'


def with_password(isolated_settings, docker_app, **world):
    isolated_settings.set_value("UserData.Audiobookshelf", "audiobookshelf_admin_pass", "secret")
    return docker_app(installers.Audiobookshelf, **world)


def test_the_env_carries_the_port_library_and_pinned_image(docker_app):
    env = docker_app(installers.Audiobookshelf).env()

    assert "AUDIOBOOKSHELF_PORT_HTTP=8084" in env
    assert "AUDIOBOOKSHELF_AUDIO_DIR=/mnt/storage/Music/Audiobook" in env
    assert "AUDIOBOOKSHELF_IMAGE=advplyr/audiobookshelf:" in env


def test_the_library_is_mounted_read_only():
    assert "${AUDIOBOOKSHELF_AUDIO_DIR}:/audiobooks:ro" in installer_audiobookshelf.docker_compose_template


def test_the_site_is_proxied_with_websockets(docker_app):
    app = docker_app(installers.Audiobookshelf)

    assert app.installer.nginx_config_template == installer_dockerapp.nginx_http_websocket_config_template
    assert "audio.joybox.test" in app.nginx()
    assert "proxy_pass http://localhost:8084" in app.nginx()


def test_a_missing_library_fails_the_settings_check(isolated_settings, docker_app):
    isolated_settings.set_value("UserData.Audiobookshelf", "audiobookshelf_audio_dir", "")

    assert not docker_app(installers.Audiobookshelf).installer.check_required_settings()


def test_only_the_config_volume_is_backed_up(docker_app):
    assert docker_app(installers.Audiobookshelf).installer.backup_volumes == ["config_data"]


def test_without_a_password_the_root_user_is_left_to_the_site(docker_app, caplog):
    app = docker_app(installers.Audiobookshelf)

    assert app.installer.post_install()
    assert app.connection.commands == []
    assert "first visitor" in caplog.text


def test_the_root_user_is_sent_through_a_private_payload(isolated_settings, docker_app):
    isolated_settings.set_value("UserData.Audiobookshelf", "audiobookshelf_admin_user", "pam")
    app = with_password(isolated_settings, docker_app, command_output = {"-X POST": "200", "/status": NEW_SERVER})

    assert app.installer.post_install()
    assert json.loads(app.connection.written(".api-payload.json")) == {
        "newRoot": {"username": "pam", "password": "secret"}}
    assert app.connection.ran("-X POST", "http://127.0.0.1:8084/init")


def test_the_wait_targets_the_status_page(isolated_settings, docker_app):
    app = with_password(isolated_settings, docker_app, command_output = {"/status": '{"isInit":true}'})

    assert app.installer.post_install()
    assert app.connection.ran("sh -c", "http://127.0.0.1:8084/status")
