# Imports
import os

# Local imports
from fakes import FakeSSHClient, FakeSFTP
from connection_ssh_helpers import build, logged


###########################################################
# Uploading a directory
###########################################################

def test_every_file_in_a_tree_is_uploaded(tmp_path):
    source = tmp_path / "app"
    (source / "config").mkdir(parents = True)
    (source / "run.sh").write_text("#!/bin/sh")
    (source / "config" / "app.conf").write_text("KEY=value")
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp))

    assert connection.transfer_files(str(source), "/opt/app") is True

    uploaded = sorted(remote for _, remote in sftp.uploaded)
    assert uploaded == ["/opt/app/config/app.conf", "/opt/app/run.sh"]


def test_a_missing_remote_directory_is_created_on_the_way(tmp_path):
    source = tmp_path / "app"
    (source / "config").mkdir(parents = True)
    (source / "config" / "app.conf").write_text("KEY=value")
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp))

    connection.transfer_files(str(source), "/opt/app")

    assert "/opt/app/config" in sftp.made_directories


def test_an_excluded_directory_is_not_uploaded(tmp_path):
    source = tmp_path / "app"
    (source / ".git").mkdir(parents = True)
    (source / ".git" / "HEAD").write_text("ref")
    (source / "run.sh").write_text("#!/bin/sh")
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp))

    connection.transfer_files(str(source), "/opt/app", excludes = [".git"])

    assert [remote for _, remote in sftp.uploaded] == ["/opt/app/run.sh"]


def privileged_upload(tmp_path, exit_code = 0):
    source = tmp_path / "app"
    source.mkdir()
    (source / "run.sh").write_text("#!/bin/sh")
    sftp = FakeSFTP()
    client = FakeSSHClient(sftp = sftp, exit_code = exit_code)
    result = build(client).transfer_files(str(source), "/opt/app", sudo = True)
    staged = os.path.dirname(sftp.uploaded[0][1])
    return result, staged, client.commands


def test_a_privileged_upload_is_staged_then_merged(tmp_path):
    # The login user cannot write into the destination, so the tree lands in
    # a temporary directory and its contents are copied in as root. A move
    # would nest the tree in an existing destination.
    result, staged, commands = privileged_upload(tmp_path)

    assert result is True
    assert staged.startswith("/tmp/transfer_")
    assert commands[0] == "sudo -n mkdir -p /opt/app"
    assert commands[1] == "sudo -n cp -r %s/. /opt/app" % staged


def test_a_privileged_upload_removes_its_staging(tmp_path):
    _, staged, commands = privileged_upload(tmp_path)

    assert commands[-1] == "rm -rf -- %s" % staged


def test_a_failed_privileged_upload_is_reported(tmp_path):
    result, staged, commands = privileged_upload(tmp_path, exit_code = 1)

    assert result is False
    assert commands[-1] == "rm -rf -- %s" % staged


def test_an_upload_without_a_connection_reports_failure(tmp_path):
    source = tmp_path / "app"
    source.mkdir()

    assert build().transfer_files(str(source), "/opt/app") is False



def test_a_failed_file_upload_fails_the_transfer(tmp_path):
    source = tmp_path / "app"
    source.mkdir()
    (source / "run.sh").write_text("#!/bin/sh")

    class FailingSFTP(FakeSFTP):
        def put(self, local, remote):
            raise IOError("disk full")

    assert build(FakeSSHClient(sftp = FailingSFTP())).transfer_files(str(source), "/opt/app") is False



###########################################################
# Single files, dry runs and failures
###########################################################

def tree(tmp_path):
    source = tmp_path / "app"
    source.mkdir()
    (source / "run.sh").write_text("#!/bin/sh")
    return source


def test_pretending_uploads_nothing(tmp_path, monkeypatch):
    lines = logged(monkeypatch)
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp), pretend_run = True, verbose = True)

    assert connection.transfer_files(str(tree(tmp_path)), "/opt/app", sudo = True) is True
    assert sftp.uploaded == []
    assert lines == ["Transferring %s to /opt/app" % (tmp_path / "app")]


def test_a_verbose_upload_logs_each_step(tmp_path, monkeypatch):
    lines = logged(monkeypatch)
    source = tree(tmp_path)

    build(FakeSSHClient(), verbose = True).transfer_files(str(source), "/opt/app")

    assert lines[1:] == [
        "Making remote directory: /opt/app",
        "Transferring file: %s to /opt/app/run.sh" % (source / "run.sh")]


def test_an_existing_remote_directory_is_not_made_again(tmp_path):
    sftp = FakeSFTP(files = {"/opt/app": ""})

    build(FakeSSHClient(sftp = sftp)).transfer_files(str(tree(tmp_path)), "/opt/app")

    assert sftp.made_directories == []


def test_a_single_file_is_uploaded_to_the_destination(tmp_path):
    source = tmp_path / "app.conf"
    source.write_text("KEY=value")
    sftp = FakeSFTP()

    assert build(FakeSSHClient(sftp = sftp)).transfer_files(str(source), "/etc/app.conf") is True
    assert sftp.uploaded == [(str(source), "/etc/app.conf")]


def test_a_privileged_single_file_is_staged_then_copied(tmp_path):
    source = tmp_path / "app.conf"
    source.write_text("KEY=value")
    sftp = FakeSFTP()
    client = FakeSSHClient(sftp = sftp)

    assert build(client).transfer_files(str(source), "/etc/app.conf", sudo = True) is True
    staged = sftp.uploaded[0][1]
    assert client.commands == ["sudo -n cp %s /etc/app.conf" % staged, "rm -rf -- %s" % staged]


def test_excluded_files_and_nested_directories_are_skipped(tmp_path):
    source = tree(tmp_path)
    (source / "debug.log").write_text("noise")
    (source / "lib" / "cache").mkdir(parents = True)
    (source / "lib" / "cache" / "blob").write_text("x")
    (source / "lib" / "mod.py").write_text("x")
    sftp = FakeSFTP()

    build(FakeSSHClient(sftp = sftp)).transfer_files(str(source), "/opt/app", excludes = [".log", "cache"])

    assert sorted(remote for _, remote in sftp.uploaded) == ["/opt/app/lib/mod.py", "/opt/app/run.sh"]
    assert "/opt/app/lib/cache" not in sftp.made_directories


def test_a_failed_privileged_upload_removes_its_staging(tmp_path):
    class FailingSFTP(FakeSFTP):
        def put(self, local, remote):
            raise IOError("disk full")
    client = FakeSSHClient(sftp = FailingSFTP())

    assert build(client).transfer_files(str(tree(tmp_path)), "/opt/app", sudo = True) is False
    assert [cmd.split()[:3] for cmd in client.commands] == [["rm", "-rf", "--"]]


def test_a_failed_privileged_merge_is_reported(tmp_path):
    class MergeFails(FakeSSHClient):
        def exec_command(self, command, get_pty = False):
            self.exit_code = 1 if " cp " in command else 0
            return super().exec_command(command, get_pty)
    client = MergeFails()

    assert build(client).transfer_files(str(tree(tmp_path)), "/opt/app", sudo = True) is False
    assert client.commands[-1].startswith("rm -rf -- /tmp/transfer_")


def test_an_upload_that_errors_closes_its_session(tmp_path):
    class Unwritable(FakeSFTP):
        def mkdir(self, path):
            raise PermissionError(path)
    sftp = Unwritable()

    assert build(FakeSSHClient(sftp = sftp)).transfer_files(str(tree(tmp_path)), "/opt/app") is False
    assert sftp.closed


def test_a_privileged_upload_that_errors_removes_its_staging(tmp_path):
    class Unwritable(FakeSFTP):
        def put(self, local, remote):
            raise PermissionError(remote)

        def mkdir(self, path):
            super().mkdir(path)
            raise PermissionError(path)
    client = FakeSSHClient(sftp = Unwritable())

    assert build(client).transfer_files(str(tree(tmp_path)), "/opt/app", sudo = True) is False
    assert client.only().startswith("rm -rf -- /tmp/transfer_")
