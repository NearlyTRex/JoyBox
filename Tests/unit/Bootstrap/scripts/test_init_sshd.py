# Imports
import os

# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")


###########################################################
# Day-0 sshd hardening
#
# init_sshd.sh closes password and root login. It must name the user whose
# key keeps the way back in, and refuse anything it does not understand
# before touching sshd.
###########################################################

SCRIPT = "Bootstrap/scripts/init_sshd.sh"
DROPIN = "/etc/ssh/sshd_config.d/00-joybox.conf"
ENFORCED = "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n"


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy")
    shell_sandbox.write("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy\n")
    shell_sandbox.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    shell_sandbox.stub("sshd", script = '[ "$1" = -T ] && printf "%s"\nexit 0\n' % ENFORCED)
    return shell_sandbox


def test_sshd_is_hardened_for_the_named_user(server):
    result = server.run(SCRIPT, "--user", "deploy")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PasswordAuthentication no" in server.read(DROPIN)
    assert server.ran("systemctl", "reload")


def test_arguments_after_the_options_are_ignored(server):
    result = server.run(SCRIPT, "--user", "deploy", "extra")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.exists(DROPIN)


@pytest.mark.parametrize("args", [[], ["extra"]])
def test_the_user_is_required(server, args):
    result = server.run(SCRIPT, *args)

    assert result.returncode == 1
    assert "--user must be specified" in result.stdout
    assert "Usage:" in result.stdout
    assert not server.exists(DROPIN)


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, "--port", "2222", "--user", "deploy")

    assert result.returncode == 1
    assert "Unknown option: --port" in result.stdout
    assert not server.exists(DROPIN)


def test_a_missing_user_is_refused(server):
    result = server.run(SCRIPT, "--user", "ghost")

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout
    assert not server.exists(DROPIN)


def test_the_script_refuses_to_run_without_its_library(shell_sandbox):
    result = shell_sandbox.run_command(
        ["bash", "-c", 'source "$1"', "/nowhere/init_sshd.sh", os.path.join(shell_sandbox.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
