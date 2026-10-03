# Third-party imports
import pytest

# Local imports
from fakes import FakeSSHClient, FakeSFTP
from connection_ssh_helpers import build, logged


###########################################################
# Remote filesystem
###########################################################

def test_the_remote_home_is_resolved_over_sftp():
    client = FakeSSHClient(sftp = FakeSFTP(home = "/home/deploy"))
    connection = build(client)

    assert connection.get_home_directory() == "/home/deploy"


def test_the_remote_home_is_only_resolved_once():
    # Every path an installer builds starts from the home, and each lookup is
    # a round trip to the server.
    sftp = FakeSFTP(home = "/home/deploy")
    connection = build(FakeSSHClient(sftp = sftp))

    connection.get_home_directory()
    sftp.home = "/somewhere/else"

    assert connection.get_home_directory() == "/home/deploy"


def test_there_is_no_remote_home_without_a_connection():
    assert build().get_home_directory() is None


def test_an_existing_remote_path_is_found():
    client = FakeSSHClient(sftp = FakeSFTP(files = {"/opt/app": ""}))
    connection = build(client)

    assert connection.does_file_or_directory_exist("/opt/app") is True


def test_a_missing_remote_path_is_not_found():
    connection = build(FakeSSHClient(sftp = FakeSFTP()))

    assert connection.does_file_or_directory_exist("/opt/absent") is False


def test_pretending_assumes_remote_paths_exist():
    connection = build(FakeSSHClient(), pretend_run = True)

    assert connection.does_file_or_directory_exist("/opt/absent") is True


def test_a_temporary_directory_is_made_on_the_server():
    client = FakeSSHClient(output = b"/tmp/tmp.XYZ\n")
    connection = build(client)

    assert connection.make_temporary_directory() == "/tmp/tmp.XYZ"
    assert client.only() == "mktemp -d"


###########################################################
# Reading and writing remote files
###########################################################

def test_a_remote_file_is_read_over_sftp():
    client = FakeSSHClient(sftp = FakeSFTP(files = {"/etc/app.conf": "contents"}))
    connection = build(client)

    assert connection.read_file("/etc/app.conf") == "contents"
    assert client.commands == []


def test_a_privileged_read_goes_through_cat():
    # sftp has no way to elevate, so a root owned file is read by running cat.
    client = FakeSSHClient(output = b"contents")
    connection = build(client)

    assert connection.read_file("/etc/shadow", sudo = True) == "contents"
    assert client.only() == "sudo -n cat /etc/shadow"


def test_a_remote_file_that_is_not_there_reads_as_nothing():
    connection = build(FakeSSHClient(sftp = FakeSFTP()))

    assert connection.read_file("/etc/absent.conf") is None


def test_pretending_reads_nothing():
    connection = build(FakeSSHClient(), pretend_run = True)

    assert connection.read_file("/etc/app.conf") is None


def test_a_remote_file_is_written_over_sftp():
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp))

    assert connection.write_file("/opt/app/.env", "KEY=value") is True
    assert sftp.written == {"/opt/app/.env": "KEY=value"}


def test_a_privileged_write_is_staged_then_copied(monkeypatch):
    # The destination directory is not writable by the login user, so the
    # file is written somewhere it can be and copied into place as root. A
    # move would hand an existing file the staged file's owner and mode.
    sftp = FakeSFTP()
    client = FakeSSHClient(sftp = sftp)
    connection = build(client)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is True

    staged = list(sftp.written.keys())[0]
    assert staged.startswith("/tmp/")
    assert sftp.written[staged] == "contents"
    assert client.only() == "sudo -n cp %s /etc/app.conf" % staged


def test_a_privileged_write_removes_the_staged_file():
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp))
    connection.write_file("/etc/app.conf", "contents", sudo = True)

    assert sftp.removed == list(sftp.written.keys())


def test_privileged_writes_do_not_share_a_staging_path():
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp))
    connection.write_file("/etc/a.conf", "a", sudo = True)
    connection.write_file("/etc/b.conf", "b", sudo = True)

    assert len(sftp.written) == 2


def test_a_failed_privileged_write_is_reported():
    connection = build(FakeSSHClient(exit_code = 1))

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False


def test_pretending_writes_nothing():
    sftp = FakeSFTP()
    connection = build(FakeSSHClient(sftp = sftp), pretend_run = True)

    assert connection.write_file("/opt/app/.env", "KEY=value") is True
    assert sftp.written == {}


###########################################################
# Remote file operations
#
# Each of these is a command built from the configured system tool, so the
# flags are what decide whether the operation is recursive or destructive.
###########################################################

def test_a_remote_directory_is_made_with_its_parents():
    client = FakeSSHClient()

    assert build(client).make_directory("/opt/app/data") is True
    assert client.only() == "mkdir -p /opt/app/data"


def test_a_remote_removal_takes_the_whole_tree():
    # The separator stops a path beginning with a dash being read as options.
    client = FakeSSHClient()

    build(client).remove_file_or_directory("/opt/app")

    assert client.only() == "rm -rf -- /opt/app"


def test_a_remote_copy_is_recursive():
    client = FakeSSHClient()

    build(client).copy_file_or_directory("/opt/a", "/opt/b")

    assert client.only() == "cp -r /opt/a /opt/b"


def test_a_remote_move_uses_the_move_tool():
    client = FakeSSHClient()

    build(client).move_file_or_directory("/opt/a", "/opt/b")

    assert client.only() == "mv /opt/a /opt/b"


def test_a_remote_link_is_forced_and_symbolic():
    client = FakeSSHClient()

    build(client).link_file_or_directory("/opt/app/current", "/usr/local/bin/app")

    assert client.only() == "ln -sf /opt/app/current /usr/local/bin/app"


def test_a_remote_download_follows_redirects_and_fails_on_http_errors():
    client = FakeSSHClient()

    build(client).download_file("https://example.test/app.tar", "/opt/app.tar")

    assert client.only() == "curl -fL -o /opt/app.tar https://example.test/app.tar"


def test_a_remote_archive_is_extracted_into_its_destination():
    client = FakeSSHClient()

    build(client).extract_tar_archive("/tmp/app.tar", "/opt/app")

    assert client.only() == "tar -xf /tmp/app.tar -C /opt/app"


def test_remote_ownership_is_changed_recursively():
    client = FakeSSHClient()

    build(client).change_owner("/opt/app", "app:app")

    assert client.only() == "chown -R app:app /opt/app"


def test_remote_permissions_are_changed_recursively():
    client = FakeSSHClient()

    build(client).change_permission("/opt/app", "750")

    assert client.only() == "chmod -R 750 /opt/app"


@pytest.mark.parametrize("method,args", [
    ("make_directory", ("/opt/app",)),
    ("remove_file_or_directory", ("/opt/app",)),
    ("copy_file_or_directory", ("/opt/a", "/opt/b")),
    ("move_file_or_directory", ("/opt/a", "/opt/b")),
    ("link_file_or_directory", ("/opt/a", "/opt/b")),
    ("change_owner", ("/opt/app", "app:app")),
    ("change_permission", ("/opt/app", "750")),
])
def test_a_remote_operation_can_be_elevated(method, args):
    client = FakeSSHClient()

    getattr(build(client), method)(*args, sudo = True)

    assert client.only().startswith("sudo ")



###########################################################
# Failures and logging
###########################################################

OPERATIONS = [
    ("make_directory", ("/opt/app",)),
    ("remove_file_or_directory", ("/opt/app",)),
    ("copy_file_or_directory", ("/opt/a", "/opt/b")),
    ("move_file_or_directory", ("/opt/a", "/opt/b")),
    ("link_file_or_directory", ("/opt/a", "/opt/b")),
    ("download_file", ("https://example.test/a", "/opt/a")),
    ("extract_tar_archive", ("/tmp/a.tar", "/opt/a")),
    ("change_owner", ("/opt/app", "app:app")),
    ("change_permission", ("/opt/app", "750")),
]


@pytest.mark.parametrize("method,args", OPERATIONS)
def test_a_failed_remote_operation_is_reported(method, args):
    # A failure is the caller's to handle unless the connection exits on failure.
    assert getattr(build(FakeSSHClient(exit_code = 1)), method)(*args, sudo = True) is False


@pytest.mark.parametrize("method,args", OPERATIONS)
def test_a_failed_remote_operation_can_quit_the_program(monkeypatch, method, args):
    logged(monkeypatch)
    connection = build(FakeSSHClient(exit_code = 1), exit_on_failure = True)

    with pytest.raises(SystemExit):
        getattr(connection, method)(*args)


def test_a_removal_path_is_never_parsed_by_a_shell():
    client = FakeSSHClient()

    build(client).remove_file_or_directory("/opt/my app; reboot")

    assert client.only() == "rm -rf -- '/opt/my app; reboot'"


def test_pretending_makes_no_temporary_directory():
    client = FakeSSHClient(output = b"/tmp/tmp.XYZ")

    assert build(client, pretend_run = True).make_temporary_directory() is None
    assert client.commands == []


def test_a_failed_temporary_directory_is_none():
    assert build(FakeSSHClient(output = b"")).make_temporary_directory() is None


def test_a_verbose_temporary_directory_is_logged(monkeypatch):
    lines = logged(monkeypatch)

    build(FakeSSHClient(output = b"/tmp/tmp.XYZ"), verbose = True).make_temporary_directory()

    assert lines[-1] == "Created temporary directory: /tmp/tmp.XYZ"


def test_a_verbose_existence_check_is_logged(monkeypatch):
    lines = logged(monkeypatch)

    build(FakeSSHClient(), verbose = True, pretend_run = True).does_file_or_directory_exist("/opt/app")

    assert lines == ["Checking existence of /opt/app"]


def test_an_existence_check_closes_its_session():
    sftp = FakeSFTP()

    build(FakeSSHClient(sftp = sftp)).does_file_or_directory_exist("/opt/absent")

    assert sftp.closed


def test_an_existence_check_that_errors_is_reported():
    class Denied(FakeSFTP):
        def stat(self, path):
            raise PermissionError(path)

    assert build(FakeSSHClient(sftp = Denied())).does_file_or_directory_exist("/root/x") is False


@pytest.mark.parametrize("method,args,message", [
    ("read_file", ("/etc/app.conf",), "Reading remote file /etc/app.conf"),
    ("write_file", ("/etc/app.conf", "x"), "Writing remote file /etc/app.conf"),
])
def test_verbose_file_access_is_logged(monkeypatch, method, args, message):
    lines = logged(monkeypatch)

    getattr(build(FakeSSHClient(), verbose = True, pretend_run = True), method)(*args)

    assert lines == [message]


def test_a_failed_read_closes_its_session():
    sftp = FakeSFTP()

    build(FakeSSHClient(sftp = sftp)).read_file("/etc/absent.conf")

    assert sftp.closed


def test_a_failed_write_closes_its_session():
    class Full(FakeSFTP):
        def file(self, path, mode = "r"):
            raise OSError("disk full")
    sftp = Full()

    assert build(FakeSSHClient(sftp = sftp)).write_file("/opt/app/.env", "KEY=value") is False
    assert sftp.closed
