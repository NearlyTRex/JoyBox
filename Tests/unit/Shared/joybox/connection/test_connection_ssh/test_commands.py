# Third-party imports
import pytest

# Local imports
from joybox.connection import connection_ssh
from fakes import FakeSSHClient, FakeChannel
from connection_ssh_helpers import build, logged


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

    assert connection.process_command("ls") == 'cd "$HOME"/apps/tool && ls'


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



def test_remote_sudo_never_waits_for_a_password():
    # A prompt over this connection can never be answered, so an ungranted
    # command has to fail rather than hang the deploy.
    client = FakeSSHClient()
    build(client).run_blocking(["systemctl", "restart", "nginx"], sudo = True)

    assert client.only().startswith("sudo -n ")


###########################################################
# Quoting, logging and failures
###########################################################

def test_the_bare_home_is_entered_through_the_remote_shell():
    connection = build()
    connection.options.cwd = "~"

    assert connection.process_command("ls") == 'cd "$HOME" && ls'


def test_a_working_directory_with_spaces_is_quoted():
    connection = build()
    connection.options.cwd = "/opt/my app; rm -rf /"

    assert connection.process_command("ls") == "cd '/opt/my app; rm -rf /' && ls"


def test_a_string_command_is_marked_for_sudo():
    assert build().mark_command_as_sudo("id") == "sudo -n id"


def test_an_unsupported_command_is_not_marked():
    assert build().mark_command_as_sudo(None) is None


RUNNERS = ["run_output", "run_return_code", "run_blocking", "run_interactive"]


class ShellClient(FakeSSHClient):
    # Keeps the interactive channel so what was sent to it can be checked.
    def invoke_shell(self):
        self.channel = FakeChannel(exit_code = self.exit_code, output = self.output)
        return self.channel


@pytest.mark.parametrize("method", RUNNERS)
def test_a_verbose_command_is_logged(monkeypatch, method):
    lines = logged(monkeypatch)
    connection = build(ShellClient(), verbose = True)

    getattr(connection, method)(["echo", "hi"])

    assert lines[0] == 'Running "echo hi"'


@pytest.mark.parametrize("method", RUNNERS)
def test_every_runner_can_be_elevated(method):
    client = ShellClient()
    getattr(build(client), method)(["id"], sudo = True)

    sent = client.channel.sent[0] if method == "run_interactive" else client.only()
    assert sent.startswith("sudo -n id")


@pytest.mark.parametrize("method", ["run_blocking", "run_interactive"])
def test_pretending_runs_nothing_interactively(method):
    client = ShellClient()

    assert getattr(build(client, pretend_run = True), method)(["false"]) == 0
    assert client.commands == [] and not hasattr(client, "channel")


@pytest.mark.parametrize("method", RUNNERS)
def test_a_failed_command_can_quit_the_program(method):
    with pytest.raises(SystemExit):
        getattr(build(exit_on_failure = True), method)(["ls"])


def test_an_interactive_shell_exits_with_the_command(monkeypatch):
    # The shell would otherwise wait for more input and the command never end.
    client = ShellClient(exit_code = 6, output = b"done\n")
    lines = logged(monkeypatch)

    assert build(client, verbose = True).run_interactive(["make"]) == 6
    assert client.channel.sent == ["make\nexit $?\n"]
    assert client.channel.closed
    assert lines[-1] == "done"


def test_an_interactive_command_is_polled_until_it_exits(monkeypatch):
    class SlowChannel(FakeChannel):
        def __init__(self):
            super().__init__(exit_code = 0)
            self.polls = 0

        def exit_status_ready(self):
            self.polls += 1
            return self.polls > 1

    class SlowClient(FakeSSHClient):
        def invoke_shell(self):
            return SlowChannel()
    naps = []
    monkeypatch.setattr(connection_ssh.time, "sleep", naps.append)

    assert build(SlowClient()).run_interactive(["make"]) == 0
    assert naps == [0.1]


def test_blocking_output_is_streamed(monkeypatch):
    streamed = []
    monkeypatch.setattr(connection_ssh.logger, "log_output", lambda text: None)
    monkeypatch.setattr(connection_ssh.logger, "record_output", streamed.append)

    build(FakeSSHClient(output = b"line one\nline two\n")).run_blocking(["build"])

    assert streamed == ["line one", "line two"]


def test_a_list_command_is_marked_for_sudo():
    assert build().mark_command_as_sudo(["id"]) == ["sudo", "-n", "id"]


def test_quiet_interactive_output_is_not_logged(monkeypatch):
    lines = logged(monkeypatch)

    assert build(FakeSSHClient(output = b"done\n")).run_interactive(["make"]) == 0
    assert lines == []
