# Imports
import os

# Third-party imports
import pytest


###########################################################
# Day-0 sudoers grant
#
# init_sudoers.sh installs the managers from this checkout and grants the
# deploy user passwordless sudo on exactly them and the managed packages,
# or removes that grant again.
###########################################################

SCRIPT = "Bootstrap/scripts/init_sudoers.sh"
SUDOERS = "/etc/sudoers.d/99-deploy-joybox"


def read_list(repo_root, name):
    with open(os.path.join(repo_root, "Bootstrap", "scripts", name)) as handle:
        return [line.strip() for line in handle if line.strip() and not line.strip().startswith("#")]


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy")
    os.makedirs(shell_sandbox.host_path("/etc/sudoers.d"))
    return shell_sandbox


def test_setup_installs_the_managers_and_grants_them(server):
    result = server.run(SCRIPT, "--action", "setup", "--user", "deploy")

    assert result.returncode == 0, result.stdout + result.stderr
    sudoers = server.read(SUDOERS)
    for manager in read_list(server.repo_root, "servermanagers.txt"):
        assert server.exists("/usr/local/bin/" + manager)
        assert "/usr/local/bin/%s" % manager in sudoers
    for package in read_list(server.repo_root, "serverpackages.txt"):
        assert "/usr/bin/apt-get install -y %s" % package in sudoers
    assert sudoers.rstrip().startswith("Cmnd_Alias APT_MANAGE")
    assert "deploy ALL=(ALL) NOPASSWD:" in sudoers
    assert not server.calls("curl")


def test_cleanup_removes_the_grant(server):
    server.write(SUDOERS, "grant\n")

    result = server.run(SCRIPT, "--action", "cleanup", "--user", "deploy")

    assert result.returncode == 0, result.stdout + result.stderr
    assert not server.exists(SUDOERS)


def test_an_unknown_action_is_refused(server):
    result = server.run(SCRIPT, "--action", "grant", "--user", "deploy")

    assert result.returncode == 1
    assert "Invalid action 'grant'" in result.stdout
    assert "Usage:" in result.stdout
    assert not server.exists(SUDOERS)


@pytest.mark.parametrize("args", [
    ["--user", "deploy"],
    ["--action", "setup"],
    ["extra", "--action", "setup", "--user", "deploy"],
])
def test_both_the_action_and_the_user_are_required(server, args):
    result = server.run(SCRIPT, *args)

    assert result.returncode == 1
    assert "Both --action and --user must be specified" in result.stdout


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, "--action", "setup", "--user", "deploy", "--all")

    assert result.returncode == 1
    assert "Unknown option: --all" in result.stdout
    assert not server.exists(SUDOERS)


def test_a_missing_user_is_refused(server):
    result = server.run(SCRIPT, "--action", "setup", "--user", "ghost")

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout
    assert not server.exists("/etc/sudoers.d/99-ghost-joybox")


def test_the_script_refuses_to_run_without_its_library(shell_sandbox):
    result = shell_sandbox.run_command(
        ["bash", "-c", 'source "$1"', "/nowhere/init_sudoers.sh", os.path.join(shell_sandbox.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
