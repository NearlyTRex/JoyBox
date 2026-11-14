# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_kanboard


###########################################################
# Kanboard
###########################################################

def with_password(isolated_settings, docker_app, **world):
    isolated_settings.set_value("UserData.Kanboard", "kanboard_admin_user", "pam")
    isolated_settings.set_value("UserData.Kanboard", "kanboard_admin_pass", "secret")
    return docker_app(installers.Kanboard, **world)


def test_the_env_quotes_the_admin_login(isolated_settings, docker_app):
    env = with_password(isolated_settings, docker_app).env()

    assert "KANBOARD_PORT_HTTP=8086" in env
    assert "KANBOARD_ADMIN_USER='pam'" in env
    assert "KANBOARD_ADMIN_PASS='secret'" in env
    assert "KANBOARD_IMAGE=kanboard/kanboard:" in env


def test_the_site_is_served_on_its_subdomain(docker_app):
    nginx = docker_app(installers.Kanboard).nginx()

    assert "tasks.joybox.test" in nginx
    assert "proxy_pass http://localhost:8086" in nginx


def test_data_and_plugins_are_both_backed_up(docker_app):
    assert docker_app(installers.Kanboard).installer.backup_volumes == ["kanboard_data", "kanboard_plugins"]


def test_the_admin_script_renames_the_default_admin():
    assert '$users->getByUsername("admin")' in installer_kanboard.admin_script
    assert '"role" => "app-admin"' in installer_kanboard.admin_script


def test_a_failed_login_reports_the_exit_code(isolated_settings, docker_app, caplog):
    app = with_password(isolated_settings, docker_app, return_codes = {"php -r": 3})

    assert not app.installer.post_install()
    assert "exit 3" in caplog.text


def test_install_without_a_password_writes_nothing(docker_app):
    app = docker_app(installers.Kanboard)

    assert not app.installer.install()
    assert app.connection.write_log == []


def test_install_starts_compose_and_marks_the_app_installed(isolated_settings, docker_app):
    app = with_password(isolated_settings, docker_app)

    assert app.installer.install()
    assert app.connection.written("/tmp/kanboard.docker-compose.yml") == installer_kanboard.docker_compose_template
    assert ("/tmp/kanboard.env", f"{app.app_dir}/.env") in app.connection.moved
    assert (f"{app.app_dir}/.env", "600") in app.connection.permissions
    assert app.connection.ran("compose --env-file", f"{app.app_dir}/.env", "up -d --build")
    assert app.connection.written(f"{app.app_dir}/.joybox-installed") == "kanboard\n"
