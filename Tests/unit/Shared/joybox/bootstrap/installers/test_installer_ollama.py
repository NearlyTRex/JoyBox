# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Ollama
###########################################################

SERVICE_PATH = "/etc/systemd/system/ollama.service"


def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Ollama(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    ollama, _ = make()
    assert ollama.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_binary(isolated_settings):
    ollama, connection = make()
    assert not ollama.is_installed()
    assert ollama.get_package_status() == {"installed": [], "missing": ["ollama"]}

    connection.existing_paths.add(ollama.ollama_binary_path)
    assert ollama.is_installed()
    assert ollama.get_package_status() == {"installed": ["ollama"], "missing": []}


def test_install_runs_the_upstream_script_with_bash(isolated_settings):
    ollama, connection = make()
    connection.existing_paths.add(ollama.ollama_binary_path)

    assert ollama.install()
    assert connection.ran("bash /tmp/ollama_install.sh")


def test_a_failed_script_fails_the_install(isolated_settings):
    ollama, _ = make(return_codes = {"ollama_install.sh": 1})
    assert not ollama.install()


def test_install_fails_when_no_binary_appears(isolated_settings):
    ollama, _ = make()
    assert not ollama.install()


def test_uninstall_stops_the_service_and_removes_everything(isolated_settings):
    ollama, connection = make()
    connection.existing_paths.update([ollama.ollama_binary_path, SERVICE_PATH])

    assert ollama.uninstall()
    assert connection.ran("systemctl stop ollama")
    assert connection.ran("systemctl disable ollama")
    assert connection.removed_paths == [ollama.ollama_binary_path, SERVICE_PATH]
    assert connection.ran("systemctl daemon-reload")
    assert connection.ran("userdel ollama")
    assert connection.ran("groupdel ollama")


def test_uninstall_of_nothing_removes_no_files(isolated_settings):
    ollama, connection = make()

    assert ollama.uninstall()
    assert connection.removed_paths == []
    assert not connection.ran("daemon-reload")
