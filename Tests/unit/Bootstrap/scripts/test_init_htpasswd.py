# Imports
import os

# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")


###########################################################
# init_htpasswd.sh
#
# Sets the login shared by the admin pages. The password is prompted for by
# default so it never reaches ps or shell history.
###########################################################

SCRIPT = "Bootstrap/scripts/init_htpasswd.sh"
HTPASSWD = "/etc/nginx/.htpasswd"


@pytest.fixture
def server(shell_sandbox):
    os.makedirs(shell_sandbox.host_path("/etc/nginx"))
    # Writes user:password to the file named after the flags, as htpasswd -b does
    shell_sandbox.stub("htpasswd", script = 'echo "$3:$4" >> "$2"\n')
    return shell_sandbox


def setup(server, *args, stdin = None):
    return server.run(SCRIPT, "--action", "setup", "--user", "admin", *args, input = stdin)


###########################################################
# Setup
###########################################################

def test_a_password_given_as_an_argument_is_used(server):
    result = setup(server, "--password", "secret")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("htpasswd", "-cbB", HTPASSWD, "admin", "secret")
    assert server.ran("chown", "root:www-data", HTPASSWD)


def test_a_password_is_read_from_a_file(server):
    server.write("/root/password", "from-file")

    result = setup(server, "--password-file", "/root/password")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("htpasswd", "-cbB", HTPASSWD, "admin", "from-file")


def test_an_unreadable_password_file_is_refused(server):
    result = setup(server, "--password-file", "/root/missing")

    assert result.returncode == 1
    assert "cannot read /root/missing" in result.stdout
    assert not server.ran("htpasswd")


def test_an_empty_password_file_is_refused(server):
    server.write("/root/password", "")

    result = setup(server, "--password-file", "/root/password")

    assert result.returncode == 1
    assert "/root/password is empty" in result.stdout
    assert not server.ran("htpasswd")


def test_the_password_is_prompted_for_when_not_given(server):
    result = setup(server, stdin = "typed\ntyped\n")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("htpasswd", "-cbB", HTPASSWD, "admin", "typed")


def test_a_mistyped_confirmation_is_refused(server):
    result = setup(server, stdin = "typed\ntypo\n")

    assert result.returncode == 1
    assert "passwords do not match" in result.stdout
    assert not server.ran("htpasswd")


def test_an_empty_prompted_password_is_refused(server):
    result = setup(server, stdin = "\n\n")

    assert result.returncode == 1
    assert "password cannot be empty" in result.stdout
    assert not server.ran("htpasswd")


def test_setup_needs_a_user(server):
    result = server.run(SCRIPT, "--action", "setup", "--password", "secret")

    assert result.returncode == 1
    assert "--user is required for setup" in result.stdout
    assert "Usage:" in result.stdout


###########################################################
# Cleanup
###########################################################

def test_cleanup_removes_the_file(server):
    server.write(HTPASSWD, "admin:hash\n")

    result = server.run(SCRIPT, "--action", "cleanup")

    assert result.returncode == 0, result.stdout + result.stderr
    assert not server.exists(HTPASSWD)
    assert "Removed htpasswd file" in result.stdout


###########################################################
# Arguments
###########################################################

def test_an_action_is_required(server):
    result = server.run(SCRIPT, "--user", "admin")

    assert result.returncode == 1
    assert "--action is required" in result.stdout


def test_an_unknown_action_is_refused(server):
    result = server.run(SCRIPT, "--action", "rotate")

    assert result.returncode == 1
    assert "Invalid action 'rotate'" in result.stdout
    assert not server.ran("htpasswd")


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, "--realm", "admin")

    assert result.returncode == 1
    assert "Unknown option: --realm" in result.stdout


def test_parsing_stops_at_the_first_positional_argument(server):
    result = server.run(SCRIPT, "extra", "--action", "cleanup")

    assert result.returncode == 1
    assert "--action is required" in result.stdout


def test_common_functions_must_sit_beside_the_script(server):
    result = server.run_command(["bash", "-c", 'source "$1"', "/nowhere/init_htpasswd.sh",
                                 "%s/%s" % (server.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
