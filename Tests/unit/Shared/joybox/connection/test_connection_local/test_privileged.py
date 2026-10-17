# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox.connection import connection_local
from connection_local_helpers import only


###########################################################
# Privileged commands
###########################################################

def test_a_command_is_marked_for_sudo(connection, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.mark_command_as_sudo(["rm", "-rf", "/tmp/x"]) == ["sudo", "rm", "-rf", "/tmp/x"]


def test_sudo_is_not_used_off_linux(connection, monkeypatch):
    # There is no sudo on Windows, and prefixing it turns every command into
    # a command that does not exist.
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: False)

    assert connection.mark_command_as_sudo(["rm", "/tmp/x"]) == ["rm", "/tmp/x"]


def test_a_privileged_directory_is_made_with_its_parents(connection, recorded):
    assert connection.make_directory("/opt/app/data", sudo = True) is True
    assert only(recorded)["cmd"] == ["/bin/mkdir", "-p", "/opt/app/data"]


def test_a_privileged_removal_takes_the_whole_tree(connection, recorded):
    # The separator keeps a path starting with a dash from being read as an
    # option, and the path is never parsed by a shell.
    connection.remove_file_or_directory("/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/rm", "-rf", "--", "/opt/app"]


def test_a_privileged_file_copy_is_not_recursive(connection, recorded, tmp_path):
    source = tmp_path / "file.txt"
    source.write_text("data")

    connection.copy_file_or_directory(str(source), "/opt/app/file.txt", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/cp", str(source), "/opt/app/file.txt"]


def test_a_privileged_directory_copy_is_recursive(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()

    connection.copy_file_or_directory(str(source), "/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/cp", "-r", str(source), "/opt/app"]


def test_a_privileged_move_uses_mv(connection, recorded):
    connection.move_file_or_directory("/tmp/file", "/opt/app/file", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/mv", "/tmp/file", "/opt/app/file"]


def test_a_privileged_link_is_forced_and_symbolic(connection, recorded):
    # Without -f an existing link is left pointing at the old target.
    connection.link_file_or_directory("/opt/app/current", "/usr/local/bin/app", sudo = True)

    assert only(recorded)["cmd"] == ["/bin/ln", "-sf", "/opt/app/current", "/usr/local/bin/app"]


def test_a_privileged_read_goes_through_cat(connection, recorded):
    connection.read_file("/etc/secret.conf", sudo = True)

    assert only(recorded)["cmd"] == ["cat", "/etc/secret.conf"]


def test_a_privileged_write_lands_at_the_destination(connection, recorded):
    # The file is written as the current user first and then copied into
    # place, because the destination directory is not writable.
    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is True

    call = only(recorded)
    assert call["cmd"][0] == "/bin/cp"
    assert call["cmd"][2] == "/etc/app.conf"
    assert call["sudo"] is True


def test_a_privileged_write_copies_rather_than_moves(connection, recorded):
    # A move would hand an existing file like /etc/hosts the staged file's
    # owner and 0600 mode; a copy keeps the destination's.
    connection.write_file("/etc/hosts", "contents", sudo = True)

    assert only(recorded)["cmd"][0] == "/bin/cp"


def test_a_privileged_write_puts_the_contents_in_the_staged_file(connection, monkeypatch):
    staged = []

    def run(cmd, sudo = False):
        with open(cmd[1], encoding = "utf-8") as handle:
            staged.append(handle.read())
        return 0

    monkeypatch.setattr(connection, "run_return_code", run)
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert staged == ["contents"]


def test_a_privileged_write_stages_a_world_readable_file(connection, monkeypatch):
    # cp gives a new destination the staged file's mode, and a system config
    # such as an xorg snippet has to be readable by more than root.
    modes = []

    def run(cmd, sudo = False):
        modes.append(os.stat(cmd[1]).st_mode & 0o777)
        return 0

    monkeypatch.setattr(connection, "run_return_code", run)
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert modes == [0o644]


def test_a_privileged_write_cleans_up_the_staged_file(connection, recorded):
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert not os.path.exists(only(recorded)["cmd"][1])


def test_a_failed_privileged_write_is_reported(connection, monkeypatch):
    monkeypatch.setattr(connection, "run_return_code", lambda cmd, sudo = False: 1)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False


def test_a_privileged_extract_names_the_destination(connection, recorded):
    connection.extract_tar_archive("/tmp/app.tar.gz", "/opt/app", sudo = True)

    assert only(recorded)["cmd"] == ["/usr/bin/tar", "-xf", "/tmp/app.tar.gz", "-C", "/opt/app"]


def test_a_privileged_download_is_moved_in_readable_by_all_and_given_to_root(connection, monkeypatch):
    # apt reads keyrings as its sandbox user, so mkstemp's private 0600 file
    # reads as "public key is not available"
    commands, modes = [], []

    def download(url, output_file, **kwargs):
        with open(output_file, "w", encoding = "utf-8") as handle:
            handle.write(url)
        return True

    def run_checked(cmd, sudo = False, throw_exception = False):
        commands.append(cmd)
        if cmd[0] == "/bin/mv":
            modes.append(stat.S_IMODE(os.stat(cmd[1]).st_mode))
    monkeypatch.setattr(connection_local.network, "download_url", download)
    monkeypatch.setattr(connection, "run_checked", run_checked)

    assert connection.download_file("https://example.test/key.gpg", "/usr/share/keyrings/key.gpg", sudo = True) is True
    assert [command[0] for command in commands] == ["/bin/mv", "/bin/chown"]
    assert commands[0][2] == commands[1][2] == "/usr/share/keyrings/key.gpg"
    assert commands[1][1] == "0:0"
    assert modes == [0o644]


def test_a_failed_privileged_download_is_not_moved(connection, recorded, monkeypatch):
    monkeypatch.setattr(
        connection_local.network, "download_url", lambda url, output_file, **kwargs: False)

    assert connection.download_file("https://example.test/app.tar", "/opt/app.tar", sudo = True) is False
    assert recorded == []


def test_a_privileged_transfer_merges_into_the_destination(connection, recorded, tmp_path):
    # "cp -r src dest" nests src inside an existing dest; copying src/. does not.
    source = tmp_path / "tree"
    source.mkdir()

    assert connection.transfer_files(str(source), "/opt/app", sudo = True) is True
    commands = [call["cmd"] for call in recorded]
    assert commands[0] == ["/bin/mkdir", "-p", "/opt/app"]
    assert commands[1][:2] == ["/bin/cp", "-r"]
    assert commands[1][2].endswith("/.")
    assert commands[1][3] == "/opt/app"
    assert all(call["sudo"] for call in recorded)


def test_a_privileged_transfer_honours_the_excludes(connection, monkeypatch, tmp_path):
    source = tmp_path / "tree"
    (source / ".git").mkdir(parents = True)
    (source / ".git" / "HEAD").write_text("ref")
    (source / "run.sh").write_text("#!/bin/sh")
    staged = []

    def run(cmd, sudo = False):
        if cmd[0] == "/bin/cp":
            staged.extend(sorted(os.listdir(cmd[2][:-2])))
        return 0

    monkeypatch.setattr(connection, "run_return_code", run)
    connection.transfer_files(str(source), "/opt/app", excludes = [".git"], sudo = True)

    assert staged == ["run.sh"]


def test_a_privileged_transfer_cleans_up_its_staging(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()
    connection.transfer_files(str(source), "/opt/app", sudo = True)

    assert not os.path.exists(recorded[1]["cmd"][2][:-2])


def test_a_privileged_file_transfer_is_a_plain_copy(connection, recorded, tmp_path):
    source = tmp_path / "app.conf"
    source.write_text("KEY=value")

    assert connection.transfer_files(str(source), "/etc/app.conf", sudo = True) is True
    assert only(recorded)["cmd"] == ["/bin/cp", str(source), "/etc/app.conf"]


def test_a_transfer_can_skip_an_existing_destination(connection, recorded, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()
    dest = tmp_path / "existing"
    dest.mkdir()
    connection.flags.skip_existing = True

    assert connection.transfer_files(str(source), str(dest), sudo = True) is True
    assert recorded == []


def test_ownership_is_changed_recursively(connection, recorded, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.change_owner("/opt/app", "app:app", sudo = True) is True
    assert only(recorded)["cmd"] == ["/bin/chown", "-R", "app:app", "/opt/app"]


def test_permissions_are_changed_recursively(connection, recorded, monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    assert connection.change_permission("/opt/app", "750", sudo = True) is True
    assert only(recorded)["cmd"] == ["/bin/chmod", "-R", "750", "/opt/app"]


@pytest.mark.parametrize("method,args", [
    ("change_owner", ("/opt/app", "app:app")),
    ("change_permission", ("/opt/app", "750")),
])
def test_ownership_and_permissions_are_skipped_off_linux(connection, recorded, monkeypatch, method, args):
    # Windows has no equivalent, and failing there would block every install.
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: False)

    assert getattr(connection, method)(*args) is True
    assert recorded == []
