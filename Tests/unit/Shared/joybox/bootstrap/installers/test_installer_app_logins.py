# Imports
import json

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_filebrowser
from joybox.bootstrap.installers import installer_jenkins
from joybox.bootstrap.installers import installer_kanboard
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# App logins
#
# Each app's first login comes from JoyBox.ini, so a fresh deploy is usable
# without a setup page that the first visitor could claim.
###########################################################

REMOTE_HOME = "/home/deploy"


def make(installer_class, flags = None, **kwargs):
    command_output = {"printf": REMOTE_HOME}
    command_output.update(kwargs.pop("command_output", {}))
    connection = RecordingConnection(command_output = command_output, **kwargs)
    return installer_class(connection, flags or runoptions.RunFlags(verbose = False)), connection


def app_dir(name):
    return f"{REMOTE_HOME}/apps/{name}"


def env_file(installer):
    return installer.env_template.format(**installer.env_values)


###########################################################
# Shared helpers
###########################################################

def test_quoted_settings_reject_a_single_quote(isolated_settings):
    isolated_settings.set_value("UserData.Kanboard", "kanboard_admin_pass", "it's secret")
    kanboard, _ = make(installers.Kanboard)
    assert not kanboard.check_required_settings()


def test_quoted_settings_accept_shell_characters(isolated_settings):
    isolated_settings.set_value("UserData.Kanboard", "kanboard_admin_pass", "pa$$ w#rd $HOME")
    kanboard, _ = make(installers.Kanboard)
    assert kanboard.check_required_settings()
    assert "KANBOARD_ADMIN_PASS='pa$$ w#rd $HOME'" in env_file(kanboard)


def test_a_local_api_call_sends_the_payload_from_a_private_file(isolated_settings):
    oscar, connection = make(installers.Oscar, command_output = {"curl": "201"})
    payload_path = f"{app_dir('oscar')}/.api-payload.json"

    assert oscar.call_local_api("POST", "http://127.0.0.1:1/user", {"password": "secret"}) == "201"
    assert connection.ran("install -m 600 /dev/null", payload_path)
    assert json.loads(connection.written(payload_path)) == {"password": "secret"}
    assert connection.ran("curl", "-X POST", f"@{payload_path}", "http://127.0.0.1:1/user")
    assert not connection.ran("curl", "secret")
    assert payload_path in connection.removed_paths


def test_a_local_api_call_reports_an_unstaged_payload(isolated_settings):
    oscar, connection = make(installers.Oscar, return_codes = {"install -m 600": 1})
    assert oscar.call_local_api("POST", "http://127.0.0.1:1/user", {}) == ""
    assert not connection.ran("curl")


def test_waiting_for_http_reports_a_timeout(isolated_settings):
    oscar, _ = make(installers.Oscar, return_codes = {"sh -c": 1})
    assert not oscar.wait_for_http("http://127.0.0.1:1/")


###########################################################
# FileBrowser
###########################################################

def test_filebrowser_needs_a_twelve_character_password(isolated_settings):
    isolated_settings.set_value("UserData.FileBrowser", "filebrowser_user_root", "/mnt/storage")
    isolated_settings.set_value("UserData.FileBrowser", "filebrowser_admin_pass", "elevenchars")
    filebrowser, _ = make(installers.FileBrowser)
    assert not filebrowser.check_required_settings()

    isolated_settings.set_value("UserData.FileBrowser", "filebrowser_admin_pass", "twelve chars")
    filebrowser, _ = make(installers.FileBrowser)
    assert filebrowser.check_required_settings()


def test_filebrowser_syncs_the_admin_from_the_environment():
    template = installer_filebrowser.docker_compose_template
    assert "/filebrowser " not in template
    assert 'users update "$$FB_ADMIN_USER" --password "$$FB_ADMIN_PASS"' in template
    assert 'users add "$$FB_ADMIN_USER" "$$FB_ADMIN_PASS"' in template
    assert "FB_PORT" in template


###########################################################
# Kanboard
###########################################################

def test_kanboard_keeps_its_data_in_named_volumes():
    template = installer_kanboard.docker_compose_template
    assert "kanboard_data:/var/www/app/data" in template
    assert "./data" not in template


def test_kanboard_requires_an_admin_password(isolated_settings):
    kanboard, _ = make(installers.Kanboard)
    assert not kanboard.check_required_settings()


def test_kanboard_sets_the_admin_login_as_the_web_user(isolated_settings):
    kanboard, connection = make(installers.Kanboard)

    assert kanboard.post_install()
    assert connection.ran("docker exec -u nginx kanboard php -r", "userModel")


def test_kanboard_fails_when_the_login_cannot_be_set(isolated_settings):
    kanboard, _ = make(installers.Kanboard, return_codes = {"php -r": 1})
    assert not kanboard.post_install()


def test_kanboard_waits_for_a_healthy_container(isolated_settings):
    kanboard, connection = make(installers.Kanboard, return_codes = {"sh -c": 1})
    assert not kanboard.post_install()
    assert not connection.ran("php -r")


###########################################################
# Jenkins
###########################################################

def test_jenkins_home_is_a_named_volume_with_backups(isolated_settings):
    jenkins, _ = make(installers.Jenkins)
    assert "jenkins_home:/var/jenkins_home" in installer_jenkins.docker_compose_template
    assert jenkins.backup_volumes == ["jenkins_home"]


def test_jenkins_skips_the_wizard_only_with_an_admin_password(isolated_settings):
    jenkins, _ = make(installers.Jenkins)
    assert jenkins.env_values["java_opts"] == ""

    isolated_settings.set_value("UserData.Jenkins", "jenkins_admin_pass", "secret")
    jenkins, _ = make(installers.Jenkins)
    assert jenkins.env_values["java_opts"] == "-Djenkins.install.runSetupWizard=false"


def test_jenkins_writes_a_readable_admin_script_before_compose(isolated_settings, monkeypatch):
    jenkins, connection = make(installers.Jenkins)
    monkeypatch.setattr(installers.DockerAppInstaller, "install", lambda self: True)
    script_path = f"{app_dir('jenkins')}/joybox-admin.groovy"

    assert jenkins.install()
    assert connection.written(script_path) == installer_jenkins.admin_script
    assert (script_path, "644") in connection.permissions


###########################################################
# FitLog
###########################################################

CREATED = "Warning: Password input may be echoed.\nCreated user 'pam'.\nOr enter this key manually: ABC\nexit=0"


def test_fitlog_without_a_login_only_explains(isolated_settings):
    fitlog, connection = make(installers.FitLog)
    assert fitlog.post_install()
    assert not connection.ran("docker exec")


def test_fitlog_creates_the_login_from_a_private_file(isolated_settings, capsys):
    isolated_settings.set_value("UserData.FitLog", "fitlog_user", "pam")
    isolated_settings.set_value("UserData.FitLog", "fitlog_pass", "a long password")
    fitlog, connection = make(installers.FitLog, command_output = {"user create": CREATED})
    password_path = f"{app_dir('fitlog')}/.login-password"

    assert fitlog.post_install()
    assert connection.written(password_path) == "a long password\na long password\n"
    assert connection.ran("docker exec -i fitlog fitlog user create", "pam", password_path)
    assert password_path in connection.removed_paths
    assert "enter this key manually: ABC" in capsys.readouterr().out


def test_fitlog_leaves_an_existing_login_alone(isolated_settings):
    isolated_settings.set_value("UserData.FitLog", "fitlog_user", "pam")
    isolated_settings.set_value("UserData.FitLog", "fitlog_pass", "a long password")
    fitlog, _ = make(installers.FitLog, command_output = {
        "user create": "error: A user already exists; use reset-password\nexit=1"})
    assert fitlog.post_install()


def test_fitlog_reports_a_failed_login(isolated_settings):
    isolated_settings.set_value("UserData.FitLog", "fitlog_user", "pam")
    isolated_settings.set_value("UserData.FitLog", "fitlog_pass", "short")
    fitlog, _ = make(installers.FitLog, command_output = {
        "user create": "error: Password must be at least 12 characters\nexit=1"})
    assert not fitlog.post_install()


###########################################################
# Oscar
###########################################################

@pytest.fixture
def oscar_login(isolated_settings):
    isolated_settings.set_value("UserData.Oscar", "oscar_user", "pam")
    isolated_settings.set_value("UserData.Oscar", "oscar_pass", "secret")


def test_oscar_without_a_screen_name_does_nothing(isolated_settings):
    oscar, connection = make(installers.Oscar)
    assert oscar.post_install()
    assert connection.commands == []


def test_oscar_creates_the_screen_name(oscar_login):
    oscar, connection = make(installers.Oscar, command_output = {"-X POST": "201"})
    assert oscar.post_install()
    assert connection.ran("-X POST", "http://127.0.0.1:18080/user")
    assert not connection.ran("-X PUT")


def test_oscar_resets_the_password_of_an_existing_screen_name(oscar_login):
    oscar, connection = make(installers.Oscar, command_output = {"-X POST": "409", "-X PUT": "204"})
    assert oscar.post_install()
    assert connection.ran("-X PUT", "http://127.0.0.1:18080/user/password")


def test_oscar_reports_a_rejected_screen_name(oscar_login):
    oscar, _ = make(installers.Oscar, command_output = {"-X POST": "400"})
    assert not oscar.post_install()


###########################################################
# Navidrome and Audiobookshelf
###########################################################

def test_navidrome_without_a_password_does_nothing(isolated_settings):
    navidrome, connection = make(installers.Navidrome)
    assert navidrome.post_install()
    assert connection.commands == []


@pytest.mark.parametrize("status, expected", [("200", True), ("403", True), ("500", False)])
def test_navidrome_creates_the_first_admin(isolated_settings, status, expected):
    isolated_settings.set_value("UserData.Navidrome", "navidrome_admin_pass", "secret")
    navidrome, connection = make(installers.Navidrome, command_output = {"-X POST": status})
    assert navidrome.post_install() is expected
    assert connection.ran("-X POST", "/auth/createAdmin")


def test_audiobookshelf_initialises_a_new_server(isolated_settings):
    isolated_settings.set_value("UserData.Audiobookshelf", "audiobookshelf_admin_pass", "secret")
    audiobookshelf, connection = make(installers.Audiobookshelf, command_output = {
        "-X POST": "200", "/status": '{"app":"audiobookshelf","isInit":false}'})
    assert audiobookshelf.post_install()
    assert connection.ran("-X POST", "/init")


def test_audiobookshelf_leaves_an_initialised_server_alone(isolated_settings):
    isolated_settings.set_value("UserData.Audiobookshelf", "audiobookshelf_admin_pass", "secret")
    audiobookshelf, connection = make(installers.Audiobookshelf, command_output = {
        "/status": '{"app":"audiobookshelf","isInit":true}'})
    assert audiobookshelf.post_install()
    assert not connection.ran("-X POST")


def test_logins_are_skipped_on_a_pretend_run(isolated_settings):
    isolated_settings.set_value("UserData.Navidrome", "navidrome_admin_pass", "secret")
    navidrome, connection = make(installers.Navidrome, flags = runoptions.RunFlags(verbose = False, pretend_run = True))
    assert navidrome.post_install()
    assert connection.commands == []
