# Imports
import os

# Third-party imports
import pytest

pytestmark = pytest.mark.requires_binary("bash", "unshare")


###########################################################
# Day-0 Storage Box mount
#
# init_storagebox.sh keys a user to a Hetzner Storage Box and mounts it.
# The account, its host and the local user are required; the paths and the
# password file are optional and pass straight through.
###########################################################

SCRIPT = "Bootstrap/scripts/init_storagebox.sh"
REQUIRED = ["--user", "deploy", "--storage-user", "u1", "--storage-host", "u1.example.de"]


@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy", uid = 1000)
    shell_sandbox.write("/etc/fstab", "")
    for name in ["ssh-copy-id", "sshpass", "sshfs"]:
        shell_sandbox.stub(name)
    shell_sandbox.stub("mountpoint", code = 1)
    return shell_sandbox


def test_the_storage_box_is_mounted_at_the_default_paths(server):
    result = server.run(SCRIPT, *REQUIRED)

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.ran("ssh-copy-id", "-p", "23", "-s", "-i", "/home/deploy/.ssh/id_rsa.pub", "u1@u1.example.de")
    assert server.read("/etc/fstab").startswith("u1@u1.example.de:/home /mnt/storage fuse.sshfs ")
    assert server.calls("sshfs")[0][-2:] == ["u1@u1.example.de:/home", "/mnt/storage"]


def test_the_optional_paths_and_password_file_are_passed_through(server):
    server.write("/root/storage.pass", "secret")

    result = server.run(SCRIPT, *REQUIRED, "--remote-path", "/backups", "--mount-path", "/mnt/backups",
                        "--password-file", "/root/storage.pass")

    assert result.returncode == 0, result.stdout + result.stderr
    assert server.read("/etc/fstab").startswith("u1@u1.example.de:/backups /mnt/backups fuse.sshfs ")
    assert server.ran("sshpass", "-f", "/root/storage.pass")


@pytest.mark.parametrize("missing", ["--user", "--storage-user", "--storage-host"])
def test_every_required_option_is_required(server, missing):
    index = REQUIRED.index(missing)
    args = REQUIRED[:index] + REQUIRED[index + 2:]

    result = server.run(SCRIPT, *args)

    assert result.returncode == 1
    assert "--user, --storage-user, and --storage-host are required" in result.stdout
    assert "Usage:" in result.stdout
    assert not server.calls("ssh-copy-id")


def test_options_after_a_bare_argument_are_not_read(server):
    result = server.run(SCRIPT, "extra", *REQUIRED)

    assert result.returncode == 1
    assert "are required" in result.stdout


def test_an_unknown_option_is_refused(server):
    result = server.run(SCRIPT, *REQUIRED, "--port", "23")

    assert result.returncode == 1
    assert "Unknown option: --port" in result.stdout
    assert not server.calls("ssh-copy-id")


def test_a_missing_user_is_refused(server):
    result = server.run(SCRIPT, "--user", "ghost", *REQUIRED[2:])

    assert result.returncode == 1
    assert "User 'ghost' does not exist" in result.stdout


def test_the_script_refuses_to_run_without_its_library(shell_sandbox):
    result = shell_sandbox.run_command(
        ["bash", "-c", 'source "$1"', "/nowhere/init_storagebox.sh", os.path.join(shell_sandbox.repo_root, SCRIPT)])

    assert result.returncode == 1
    assert "Cannot find or read /nowhere/common.sh" in result.stdout
