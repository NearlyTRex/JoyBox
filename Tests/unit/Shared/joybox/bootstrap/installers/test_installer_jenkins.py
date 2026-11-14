# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_jenkins


###########################################################
# Jenkins
###########################################################

def test_the_env_carries_the_ports_and_repositories(docker_app):
    env = docker_app(installers.Jenkins).env()

    assert "JENKINS_PORT_HTTP=8083" in env
    assert "JENKINS_PORT_AGENT=50000" in env
    assert "JENKINS_REPOSITORIES_DIR=/mnt/repositories" in env
    assert "JENKINS_IMAGE=jenkins/jenkins:" in env


def test_both_ports_stay_on_loopback():
    template = installer_jenkins.docker_compose_template

    assert '"127.0.0.1:${JENKINS_PORT_HTTP}:8080"' in template
    assert '"127.0.0.1:${JENKINS_PORT_AGENT}:50000"' in template


def test_the_repositories_are_mounted_read_only():
    assert "${JENKINS_REPOSITORIES_DIR}:/mnt/repositories:ro" in installer_jenkins.docker_compose_template


def test_the_site_is_served_on_its_subdomain(docker_app):
    nginx = docker_app(installers.Jenkins).nginx()

    assert "tools.joybox.test" in nginx
    assert "proxy_pass http://localhost:8083" in nginx


def test_a_missing_agent_port_fails_the_settings_check(isolated_settings, docker_app):
    isolated_settings.set_value("UserData.Jenkins", "jenkins_port_agent", "")

    assert not docker_app(installers.Jenkins).installer.check_required_settings()


def test_workspaces_and_caches_are_left_out_of_backups(docker_app):
    script = docker_app(installers.Jenkins).installer.build_backup_script()

    assert "jenkins_jenkins_home:/src:ro" in script
    assert "--exclude=./workspace --exclude=./caches" in script


def test_without_a_password_the_wizard_is_announced(docker_app, monkeypatch, caplog):
    monkeypatch.setattr(installers.DockerAppInstaller, "install", lambda self: True)

    assert docker_app(installers.Jenkins).installer.install()
    assert "setup wizard" in caplog.text


def test_a_failed_compose_install_fails_after_the_script_is_written(docker_app, monkeypatch):
    app = docker_app(installers.Jenkins)
    monkeypatch.setattr(installers.DockerAppInstaller, "install", lambda self: False)

    assert not app.installer.install()
    assert app.app_dir in app.connection.made_directories
    assert app.connection.written("joybox-admin.groovy") == installer_jenkins.admin_script
