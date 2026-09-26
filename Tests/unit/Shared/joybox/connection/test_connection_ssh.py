# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection_ssh
from fakes import FakeSSHClient, FakeSFTP, FakeTransport


###########################################################
# ConnectionSSH
#
# Every operation on a server goes out as a shell command or an sftp call.
# The client is shared on the class, so a test that leaves one attached hands
# it to whatever runs next.
###########################################################

@pytest.fixture(autouse = True)
def no_shared_client():
    connection_ssh.ConnectionSSH.ssh_client = None
    yield
    connection_ssh.ConnectionSSH.ssh_client = None


def build(client = None, **flag_overrides):
    flags = runoptions.RunFlags(verbose = False, exit_on_failure = False)
    for key, value in flag_overrides.items():
        setattr(flags, key, value)
    connection = connection_ssh.ConnectionSSH(
        ssh_host = "server.test",
        ssh_user = "deploy",
        ssh_password = "unused",
        flags = flags,
        options = runoptions.RunOptions())
    if client is not None:
        connection_ssh.ConnectionSSH.ssh_client = client
    return connection


###########################################################
# Building the remote command
###########################################################

def test_a_plain_command_is_sent_as_it_is():
    connection = build()

    assert connection.process_command("ls -la") == "ls -la"


def test_a_working_directory_is_entered_first():
    connection = build()
    connection.options.cwd = "/opt/app"

    assert connection.process_command("ls") == "cd /opt/app && ls"


def test_a_home_relative_directory_is_expanded_by_the_remote_shell():
    # The local ~ means nothing on the server, and sftp would take it as a
    # directory actually named "~".
    connection = build()
    connection.options.cwd = "~/apps/tool"

    assert connection.process_command("ls") == "cd $HOME/apps/tool && ls"


def test_environment_variables_are_exported_before_the_command():
    connection = build()
    connection.options.env = {"TOKEN": "abc"}

    assert connection.process_command("ls") == "export TOKEN=abc && ls"


def test_an_environment_value_is_quoted():
    # An unquoted value with a space becomes a second export, and one with a
    # semicolon becomes a second command.
    connection = build()
    connection.options.env = {"NOTE": "two words; rm -rf /"}

    assert connection.process_command("ls") == \
        "export NOTE='two words; rm -rf /' && ls"


def test_the_environment_comes_before_the_directory():
    connection = build()
    connection.options.env = {"TOKEN": "abc"}
    connection.options.cwd = "/opt/app"

    assert connection.process_command("ls") == "export TOKEN=abc && cd /opt/app && ls"


###########################################################
# Running commands
###########################################################

def test_output_is_read_back():
    client = FakeSSHClient(output = b"  result  ")
    connection = build(client)

    assert connection.run_output(["echo", "result"]) == "result"


def test_a_command_is_sent_as_one_posix_string():
    client = FakeSSHClient()
    connection = build(client)

    connection.run_output(["ls", "-la", "/opt/my app"])

    assert client.only() == "ls -la '/opt/my app'"


def test_standard_error_is_left_out_by_default():
    client = FakeSSHClient(output = b"fine", error = b"oops")
    connection = build(client)

    assert connection.run_output(["ls"]) == "fine"


def test_standard_error_can_be_included():
    client = FakeSSHClient(output = b"fine", error = b"oops")
    connection = build(client)
    connection.options.include_stderr = True

    assert connection.run_output(["ls"]) == "fine\noops"


def test_no_error_output_adds_no_blank_line():
    client = FakeSSHClient(output = b"fine", error = b"")
    connection = build(client)
    connection.options.include_stderr = True

    assert connection.run_output(["ls"]) == "fine"


def test_a_shell_command_asks_for_a_terminal():
    # Some remote tools only produce output when they believe they have a tty.
    client = FakeSSHClient()
    connection = build(client)
    connection.options.shell = True

    connection.run_output(["ls"])

    assert client.ptys == [True]


def test_an_exit_code_is_read_back():
    client = FakeSSHClient(exit_code = 3)
    connection = build(client)

    assert connection.run_return_code(["false"]) == 3


def test_a_blocking_command_reports_its_code():
    client = FakeSSHClient(exit_code = 4, output = b"working\n")
    connection = build(client)

    assert connection.run_blocking(["build"]) == 4


def test_an_interactive_command_reports_its_code():
    client = FakeSSHClient(exit_code = 5)
    connection = build(client)

    assert connection.run_interactive(["top"]) == 5


def test_a_command_is_marked_for_sudo():
    client = FakeSSHClient()
    connection = build(client)

    connection.run_output(["systemctl", "restart", "app"], sudo = True)

    assert client.only().startswith("sudo ")


def test_the_working_directory_reaches_the_remote_command():
    client = FakeSSHClient()
    connection = build(client)
    connection.options.cwd = "/opt/app"

    connection.run_output(["ls"])

    assert client.only() == "cd /opt/app && ls"


###########################################################
# Running without a connection
###########################################################

def test_output_without_a_connection_is_empty():
    assert build().run_output(["ls"]) == ""


def test_an_exit_code_without_a_connection_reports_failure():
    assert build().run_return_code(["ls"]) == 1


@pytest.mark.parametrize("method", ["run_blocking", "run_interactive"])
def test_running_without_a_connection_reports_failure(method):
    assert getattr(build(), method)(["ls"]) == 1


def test_running_without_a_connection_can_quit_the_program():
    connection = build(exit_on_failure = True)

    with pytest.raises(SystemExit):
        connection.run_output(["ls"])


###########################################################
# Dry runs
###########################################################

def test_pretending_sends_no_command():
    client = FakeSSHClient()
    connection = build(client, pretend_run = True)

    assert connection.run_output(["rm", "-rf", "/opt/app"]) == ""
    assert client.commands == []


def test_pretending_reports_success():
    client = FakeSSHClient(exit_code = 1)
    connection = build(client, pretend_run = True)

    assert connection.run_return_code(["false"]) == 0
    assert client.commands == []


###########################################################
# Checked commands
###########################################################

def test_a_checked_command_that_fails_quits_the_program():
    connection = build(FakeSSHClient(exit_code = 1))

    with pytest.raises(SystemExit):
        connection.run_checked(["false"])


def test_a_checked_command_can_raise_instead():
    connection = build(FakeSSHClient(exit_code = 1))

    with pytest.raises(ValueError):
        connection.run_checked(["false"], throw_exception = True)


def test_a_checked_command_that_succeeds_returns():
    connection = build(FakeSSHClient())

    assert connection.run_checked(["true"]) is None


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
    assert client.only() == "sudo -n /bin/cp %s /etc/app.conf" % staged


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
    assert client.only() == "/bin/mkdir -p /opt/app/data"


def test_a_remote_removal_takes_the_whole_tree():
    # The separator stops a path beginning with a dash being read as options.
    client = FakeSSHClient()

    build(client).remove_file_or_directory("/opt/app")

    assert client.only() == "sh -c '/bin/rm -rf -- /opt/app'"


def test_a_remote_copy_is_recursive():
    client = FakeSSHClient()

    build(client).copy_file_or_directory("/opt/a", "/opt/b")

    assert client.only() == "/bin/cp -r /opt/a /opt/b"


def test_a_remote_move_uses_the_move_tool():
    client = FakeSSHClient()

    build(client).move_file_or_directory("/opt/a", "/opt/b")

    assert client.only() == "/bin/mv /opt/a /opt/b"


def test_a_remote_link_is_forced_and_symbolic():
    client = FakeSSHClient()

    build(client).link_file_or_directory("/opt/app/current", "/usr/local/bin/app")

    assert client.only() == "/bin/ln -sf /opt/app/current /usr/local/bin/app"


def test_a_remote_download_follows_redirects(monkeypatch):
    monkeypatch.setattr(
        connection_ssh.programs, "get_tool_program", lambda name: "/usr/bin/curl")
    client = FakeSSHClient()

    build(client).download_file("https://example.test/app.tar", "/opt/app.tar")

    assert client.only() == "/usr/bin/curl -L -o /opt/app.tar https://example.test/app.tar"


def test_a_remote_archive_is_extracted_into_its_destination(monkeypatch):
    monkeypatch.setattr(
        connection_ssh.programs, "get_tool_program", lambda name: "/usr/bin/tar")
    client = FakeSSHClient()

    build(client).extract_tar_archive("/tmp/app.tar", "/opt/app")

    assert client.only() == "/usr/bin/tar -xf /tmp/app.tar -C /opt/app"


def test_remote_ownership_is_changed_recursively():
    client = FakeSSHClient()

    build(client).change_owner("/opt/app", "app:app")

    assert client.only() == "/bin/chown -R app:app /opt/app"


def test_remote_permissions_are_changed_recursively():
    client = FakeSSHClient()

    build(client).change_permission("/opt/app", "750")

    assert client.only() == "/bin/chmod -R 750 /opt/app"


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
    assert commands[0] == "sudo -n /bin/mkdir -p /opt/app"
    assert commands[1] == "sudo -n /bin/cp -r %s/. /opt/app" % staged


def test_a_privileged_upload_removes_its_staging(tmp_path):
    _, staged, commands = privileged_upload(tmp_path)

    assert commands[-1] == "/bin/rm -rf %s" % staged


def test_a_failed_privileged_upload_is_reported(tmp_path):
    result, staged, commands = privileged_upload(tmp_path, exit_code = 1)

    assert result is False
    assert commands[-1] == "/bin/rm -rf %s" % staged


def test_an_upload_without_a_connection_reports_failure(tmp_path):
    source = tmp_path / "app"
    source.mkdir()

    assert build().transfer_files(str(source), "/opt/app") is False


###########################################################
# Connecting
#
# Provisioning asks whether a login works as a normal question - root on a
# hardened server is refused by design - so probing must not raise or log.
###########################################################

class RefusingClient(FakeSSHClient):
    def __init__(self):
        super().__init__()
        self.connects = []

    def set_missing_host_key_policy(self, policy):
        pass

    def get_transport(self):
        return None

    def connect(self, host, **kwargs):
        self.connects.append((host, kwargs))
        raise PermissionError("Authentication failed.")


class AcceptingClient(RefusingClient):
    def __init__(self):
        super().__init__()
        self.connected = False

    def get_transport(self):
        return FakeTransport(active = self.connected)

    def connect(self, host, **kwargs):
        self.connects.append((host, kwargs))
        self.connected = True


def fake_paramiko(monkeypatch, client):
    class Module:
        class AutoAddPolicy:
            pass

        @staticmethod
        def SSHClient():
            return client

    monkeypatch.setattr(connection_ssh, "paramiko", Module)
    return client


def test_a_refused_login_is_an_answer_not_an_error(monkeypatch):
    client = fake_paramiko(monkeypatch, RefusingClient())
    errors = []
    monkeypatch.setattr(connection_ssh.logger, "log_error", lambda *a, **k: errors.append(a))

    assert build().try_setup() is False
    assert errors == []


def test_a_refused_login_leaves_no_client_behind(monkeypatch):
    fake_paramiko(monkeypatch, RefusingClient())
    build().try_setup()

    assert connection_ssh.ConnectionSSH.ssh_client is None


def test_an_accepted_login_is_reported(monkeypatch):
    client = fake_paramiko(monkeypatch, AcceptingClient())

    assert build().try_setup() is True
    assert client.connects[0][0] == "server.test"


def test_probing_gives_up_rather_than_hanging(monkeypatch):
    client = fake_paramiko(monkeypatch, AcceptingClient())
    build().try_setup(timeout = 7)

    assert client.connects[0][1]["timeout"] == 7


def test_a_live_connection_is_reused(monkeypatch):
    client = fake_paramiko(monkeypatch, AcceptingClient())
    connection = build()
    connection.connect()
    connection.connect()

    assert len(client.connects) == 1


def test_teardown_without_a_transport_does_not_fail(monkeypatch):
    errors = []
    monkeypatch.setattr(connection_ssh.logger, "log_error", lambda *a, **k: errors.append(a))
    build(RefusingClient()).teardown()

    assert errors == []
    assert connection_ssh.ConnectionSSH.ssh_client is None


def test_a_failed_file_upload_fails_the_transfer(tmp_path):
    source = tmp_path / "app"
    source.mkdir()
    (source / "run.sh").write_text("#!/bin/sh")

    class FailingSFTP(FakeSFTP):
        def put(self, local, remote):
            raise IOError("disk full")

    assert build(FakeSSHClient(sftp = FailingSFTP())).transfer_files(str(source), "/opt/app") is False


def test_remote_sudo_never_waits_for_a_password():
    # A prompt over this connection can never be answered, so an ungranted
    # command has to fail rather than hang the deploy.
    client = FakeSSHClient()
    build(client).run_blocking(["systemctl", "restart", "nginx"], sudo = True)

    assert client.only().startswith("sudo -n ")
