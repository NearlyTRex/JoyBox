# Third-party imports
import pytest


###########################################################
# init_docker.sh
#
# Installs Docker on a fresh server, lets the account use it and locks the
# daemon down.
###########################################################

SCRIPT = "Bootstrap/scripts/init_docker.sh"


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy")
    shell_sandbox.stub("groups", stdout = "deploy : deploy\n")
    return shell_sandbox


def test_docker_is_installed_then_configured_for_the_user(server):
    result = server.run(SCRIPT, "--user", "deploy")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("apt-get", "install", "-y", "docker.io")
    assert server.ran("usermod", "-aG", "docker", "deploy")
    assert server.exists("/etc/docker/daemon.json")
    assert server.ran("systemctl", "restart", "docker")


def test_a_missing_user_stops_before_anything_is_installed(server):
    result = server.run(SCRIPT, "--user", "ghost")

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout
    assert not server.ran("apt-get")


def test_the_user_is_required(server):
    result = server.run(SCRIPT)

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout
    assert "Usage:" in result.stdout


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, "--group", "docker")

    assert result.returncode == 1
    assert "Unknown option: --group" in result.stdout


def test_parsing_stops_at_the_first_positional_argument(server):
    result = server.run(SCRIPT, "extra", "--user", "deploy")

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout


def test_common_functions_must_sit_beside_the_script(server):
    result = server.run_command(["bash", "-c", 'source "$1"', "/nowhere/init_docker.sh",
                                 "%s/%s" % (server.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
