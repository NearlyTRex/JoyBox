# Imports
import os

# Third-party imports
import pytest


###########################################################
# init_localstorage.sh
#
# Stands in for the Storage Box on the rehearsal VM with a plain directory.
###########################################################

SCRIPT = "Bootstrap/scripts/init_localstorage.sh"


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy")
    return shell_sandbox


def test_storage_is_created_at_the_default_mount_path(server):
    result = server.run(SCRIPT, "--user", "deploy")

    assert result.returncode == 0, result.stdout + result.stderr
    assert os.path.isdir(server.host_path("/mnt/storage/Music/Audiobook"))
    assert os.path.isdir(server.host_path("/mnt/storage/Backups"))
    assert server.ran("chown", "-R", "deploy:deploy", "/mnt/storage")


def test_the_mount_path_can_be_chosen(server):
    result = server.run(SCRIPT, "--user", "deploy", "--mount-path", "/srv/storage")

    assert result.returncode == 0
    assert os.path.isdir(server.host_path("/srv/storage/Backups"))
    assert not server.exists("/mnt/storage")


def test_a_missing_user_is_refused(server):
    result = server.run(SCRIPT, "--user", "ghost")

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout
    assert not server.exists("/mnt/storage")


def test_the_user_is_required(server):
    result = server.run(SCRIPT)

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout
    assert "sudo" in result.stdout and "--user alice" in result.stdout


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, "--size", "10G")

    assert result.returncode == 1
    assert "Unknown option: --size" in result.stdout


def test_parsing_stops_at_the_first_positional_argument(server):
    result = server.run(SCRIPT, "extra", "--user", "deploy")

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout


def test_common_functions_must_sit_beside_the_script(server):
    result = server.run_command(["bash", "-c", 'source "$1"', "/nowhere/init_localstorage.sh",
                                 "%s/%s" % (server.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
