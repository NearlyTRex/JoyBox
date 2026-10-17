# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import knownhosts


###########################################################
# Known SSH hosts
#
# A server is trusted the first time it is seen and its key recorded where
# ssh, paramiko and rclone all read it, so a fresh machine can reach its
# servers and a key that later changes is refused by all three.
###########################################################

SCANNED = (
    "# storage.example:23 SSH-2.0-OpenSSH_9.6\n"
    "[storage.example]:23 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTests\n"
    "[storage.example]:23 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABFakeRsaKeyForTests\n")


@pytest.fixture
def ssh(monkeypatch, tmp_path):
    # The two ssh commands, faked: what known_hosts already holds, and what a scan sees
    state = {"known": "", "scanned": SCANNED, "calls": [], "path": tmp_path / ".ssh" / "known_hosts"}
    monkeypatch.setattr(knownhosts, "get_known_hosts_path", lambda: str(state["path"]))
    monkeypatch.setattr(knownhosts, "_checked", set())

    def run_output_command(cmd, **kwargs):
        state["calls"].append(cmd)
        return state["known"] if cmd[0] == "ssh-keygen" else state["scanned"]

    monkeypatch.setattr(knownhosts.command, "run_output_command", run_output_command)
    return state


def scans(ssh):
    return [cmd for cmd in ssh["calls"] if cmd[0] == "ssh-keyscan"]


@pytest.mark.parametrize("port, entry", [(22, "box.example"), ("22", "box.example"), (23, "[box.example]:23")])
def test_a_host_is_recorded_under_ssh_s_own_name_for_it(port, entry):
    assert knownhosts.get_host_entry("box.example", port) == entry


def test_a_new_server_is_scanned_and_remembered(ssh):
    assert knownhosts.remember_host("storage.example", 23)

    assert scans(ssh) == [["ssh-keyscan", "-T", "10", "-p", "23", "storage.example"]]
    assert ssh["path"].read_text() == (
        "[storage.example]:23 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTests\n"
        "[storage.example]:23 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABFakeRsaKeyForTests\n")


def test_a_new_ssh_directory_is_made_private(ssh):
    assert knownhosts.remember_host("storage.example", 23)

    assert oct(os.stat(ssh["path"].parent).st_mode & 0o777) == "0o700"


def test_a_remembered_server_is_not_scanned_again(ssh):
    ssh["path"].parent.mkdir()
    ssh["path"].write_text("existing\n")
    ssh["known"] = "[storage.example]:23 ssh-ed25519 AAAA...\n"

    assert knownhosts.remember_host("storage.example", 23)

    assert scans(ssh) == []
    assert ssh["calls"][0] == ["ssh-keygen", "-F", "[storage.example]:23", "-f", str(ssh["path"])]


def test_a_server_is_looked_up_once_per_run(ssh):
    assert knownhosts.remember_host("storage.example", 23)
    calls = len(ssh["calls"])

    assert knownhosts.remember_host("storage.example", 23)

    assert len(ssh["calls"]) == calls


def test_a_server_that_shows_no_key_is_not_trusted(ssh):
    ssh["scanned"] = "# storage.example:23 SSH-2.0-OpenSSH_9.6\n"

    assert not knownhosts.remember_host("storage.example", 23)

    assert not ssh["path"].exists()


def test_a_key_that_cannot_be_recorded_is_not_trusted(ssh, monkeypatch):
    monkeypatch.setattr(knownhosts.fileops, "touch_file", lambda *args, **kwargs: False)

    assert not knownhosts.remember_host("storage.example", 23)
    assert "[storage.example]:23" not in knownhosts._checked


def test_a_pretend_run_contacts_no_server(ssh):
    assert knownhosts.remember_host("storage.example", 23, pretend_run = True)

    assert scans(ssh) == []
    assert not ssh["path"].exists()


def test_a_new_server_is_added_after_the_ones_already_known(ssh):
    ssh["path"].parent.mkdir()
    ssh["path"].write_text("old.example ssh-ed25519 AAAAexisting\n")

    assert knownhosts.remember_host("storage.example", 23)

    assert ssh["path"].read_text().startswith("old.example ssh-ed25519 AAAAexisting\n[storage.example]:23 ")
