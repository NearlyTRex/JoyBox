# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Ollama tunnel
#
# The LLM server's API has no authentication and listens on its own
# localhost; this tunnel, authenticated by the SSH key, is the only way to it.
###########################################################

HOST = "aryie@192.168.1.15"


def make(isolated_settings, host = HOST, port = "11444", **kwargs):
    isolated_settings.set_value("Tools.Ollama", "ollama_ssh_host", host)
    isolated_settings.set_value("Tools.Ollama", "ollama_tunnel_port", port)
    connection = RecordingConnection(**kwargs)
    return installers.OllamaTunnel(connection), connection


def exec_start(tunnel):
    line = next(line for line in tunnel.build_unit().splitlines() if line.startswith("ExecStart="))
    return line[len("ExecStart="):].split()


def test_only_local_ubuntu_is_supported(isolated_settings):
    tunnel, _ = make(isolated_settings)
    assert tunnel.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_unit_is_a_user_service(isolated_settings):
    tunnel, _ = make(isolated_settings)
    assert tunnel.unit_path == os.path.join(os.path.expanduser("~"), ".config", "systemd", "user", "ollama-tunnel.service")


###########################################################
# The tunnel
###########################################################

def test_the_api_and_helper_are_forwarded_on_localhost_only(isolated_settings):
    # The local ends must not be reachable from the network either.
    cmd = exec_start(make(isolated_settings)[0])
    forwards = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-L"]

    assert forwards == ["127.0.0.1:11444:127.0.0.1:11434", "127.0.0.1:11435:127.0.0.1:11435"]


def test_the_api_port_comes_from_the_settings(isolated_settings):
    cmd = exec_start(make(isolated_settings, port = "12000")[0])

    assert "127.0.0.1:12000:127.0.0.1:11434" in cmd


def test_the_tunnel_fails_rather_than_hangs_or_runs_without_forwards(isolated_settings):
    cmd = exec_start(make(isolated_settings)[0])

    assert cmd[:2] == ["/usr/bin/ssh", "-N"]
    assert "BatchMode=yes" in cmd
    assert "ExitOnForwardFailure=yes" in cmd
    assert cmd[-1] == HOST


def test_systemd_brings_the_tunnel_back(isolated_settings):
    unit = make(isolated_settings)[0].build_unit()

    assert "Restart=always" in unit
    assert "WantedBy=default.target" in unit


###########################################################
# Install
###########################################################

def test_install_writes_and_starts_the_unit(isolated_settings):
    tunnel, connection = make(isolated_settings)

    assert tunnel.install()
    assert connection.written(tunnel.unit_path) == tunnel.build_unit()
    assert connection.ran("systemctl --user daemon-reload")
    assert connection.ran("systemctl --user enable --now ollama-tunnel.service")
    assert not any(call[2].get("sudo") for call in connection.calls)


def test_no_server_means_nothing_to_install(isolated_settings):
    tunnel, connection = make(isolated_settings, host = "")

    assert tunnel.install()
    assert connection.commands == []
    assert connection.write_log == []


def test_a_failed_start_fails_the_install(isolated_settings):
    tunnel, connection = make(isolated_settings, return_codes = {"enable --now": 1})

    assert not tunnel.install()


###########################################################
# Status and uninstall
###########################################################

def test_status_follows_the_unit_file(isolated_settings):
    tunnel, connection = make(isolated_settings)
    assert tunnel.get_package_status() == {"installed": [], "missing": ["ollama-tunnel"]}

    connection.existing_paths.add(tunnel.unit_path)
    assert tunnel.is_installed()
    assert tunnel.get_package_status() == {"installed": ["ollama-tunnel"], "missing": []}


def test_uninstall_stops_and_removes_the_unit(isolated_settings):
    tunnel, connection = make(isolated_settings)
    connection.existing_paths.add(tunnel.unit_path)

    assert tunnel.uninstall()
    assert connection.ran("systemctl --user disable --now ollama-tunnel.service")
    assert connection.removed_paths == [tunnel.unit_path]


def test_uninstall_of_nothing_succeeds(isolated_settings):
    tunnel, connection = make(isolated_settings)

    assert tunnel.uninstall()
    assert connection.commands == []
