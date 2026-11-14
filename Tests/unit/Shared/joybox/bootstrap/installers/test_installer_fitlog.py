# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_fitlog


###########################################################
# FitLog
###########################################################

ENROLLED = "Warning: Password input may be echoed.\nCreated user 'pam'.\nKey: ABC\nexit=0"


def with_login(isolated_settings, docker_app, **world):
    isolated_settings.set_value("UserData.FitLog", "fitlog_user", "pam")
    isolated_settings.set_value("UserData.FitLog", "fitlog_pass", "a long password")
    return docker_app(installers.FitLog, **world)


def test_the_env_carries_the_catalog_and_schedule(docker_app):
    env = docker_app(installers.FitLog).env()

    assert "FITLOG_REPOSITORY=https://github.com/NearlyTRex/FitLog.git" in env
    assert "FITLOG_CATALOG_BRANCH=main" in env
    assert "FITLOG_PORT_HTTP=8087" in env
    assert "FITLOG_TIMEZONE=America/Los_Angeles" in env
    assert "FITLOG_PULL_MINUTES=10" in env


def test_compose_builds_the_pinned_tag_from_the_repository():
    assert "context: ${FITLOG_REPOSITORY}#${FITLOG_VERSION}" in installer_fitlog.docker_compose_template
    assert 'FITLOG_TRUST_PROXY: "1"' in installer_fitlog.docker_compose_template


def test_the_site_is_served_on_its_subdomain(docker_app):
    nginx = docker_app(installers.FitLog).nginx()

    assert "fit.joybox.test" in nginx
    assert "proxy_pass http://localhost:8087" in nginx


def test_a_blank_timezone_fails_the_settings_check(isolated_settings, docker_app):
    isolated_settings.set_value("UserData.FitLog", "fitlog_timezone", "")

    assert not docker_app(installers.FitLog).installer.check_required_settings()


def test_only_the_state_volume_is_backed_up(docker_app):
    assert docker_app(installers.FitLog).installer.backup_volumes == ["fitlog_state"]


def test_without_a_login_the_create_command_is_shown(docker_app, caplog):
    app = docker_app(installers.FitLog)

    assert app.installer.post_install()
    assert f"cd {app.app_dir} && docker compose exec fitlog fitlog user create <name>" in caplog.text


def test_only_the_enrolment_is_shown(isolated_settings, docker_app, capsys):
    app = with_login(isolated_settings, docker_app, command_output = {"user create": ENROLLED})

    assert app.installer.post_install()
    output = capsys.readouterr().out
    assert "Created user 'pam'.\nKey: ABC\n" in output
    assert "echoed" not in output
    assert "exit=0" not in output


def test_the_staged_password_is_removed_after_a_failure(isolated_settings, docker_app):
    app = with_login(isolated_settings, docker_app, command_output = {"user create": "boom\nexit=1"})

    assert not app.installer.post_install()
    assert f"{app.app_dir}/.login-password" in app.connection.removed_paths
