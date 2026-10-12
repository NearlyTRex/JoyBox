# Third-party imports
import pytest


###########################################################
# init_joybox.sh
#
# Clones the JoyBox repository for the account that will run it.
###########################################################

SCRIPT = "Bootstrap/scripts/init_joybox.sh"


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy")
    return shell_sandbox


def test_the_repository_is_cloned_as_the_user(server):
    result = server.run(SCRIPT, "--user", "deploy")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("chown", "deploy:deploy", "/mnt/repositories")
    assert server.ran("git", "clone", "https://github.com/NearlyTRex/JoyBox", "/mnt/repositories/JoyBox")


def test_an_existing_clone_is_kept(server):
    server.write("/mnt/repositories/JoyBox/.git/HEAD", "ref: refs/heads/main\n")

    result = server.run(SCRIPT, "--user", "deploy")

    assert result.returncode == 0
    assert "already exists" in result.stdout
    assert not server.ran("git")


def test_a_missing_user_is_refused(server):
    result = server.run(SCRIPT, "--user", "ghost")

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout
    assert not server.ran("git")


def test_the_user_is_required(server):
    result = server.run(SCRIPT)

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout
    assert "Usage:" in result.stdout


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, "--branch", "dev")

    assert result.returncode == 1
    assert "Unknown option: --branch" in result.stdout


def test_parsing_stops_at_the_first_positional_argument(server):
    result = server.run(SCRIPT, "extra", "--user", "deploy")

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout


def test_common_functions_must_sit_beside_the_script(server):
    result = server.run_command(["bash", "-c", 'source "$1"', "/nowhere/init_joybox.sh",
                                 "%s/%s" % (server.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
