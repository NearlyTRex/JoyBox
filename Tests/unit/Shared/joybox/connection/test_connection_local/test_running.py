# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection_local
from connection_local_helpers import FakeProcesses, only


###########################################################
# Environment
###########################################################

def test_the_process_environment_is_inherited():
    # A command started without an environment loses PATH, and every tool
    # lookup that follows fails.
    connection = connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False), runoptions.RunOptions())

    assert connection.options.env.get("PATH") == os.environ.get("PATH")


def test_an_explicit_environment_is_kept():
    options = runoptions.RunOptions()
    options.env = {"ONLY": "this"}

    connection = connection_local.ConnectionLocal(runoptions.RunFlags(verbose = False), options)

    assert connection.options.env == {"ONLY": "this"}


def test_the_callers_options_are_left_alone():
    options = runoptions.RunOptions()

    connection_local.ConnectionLocal(runoptions.RunFlags(verbose = False), options)

    assert options.env == {}


def test_the_local_path_separator_is_the_platforms_own(connection):
    assert connection.get_path_separator() == os.sep


###########################################################
# Running commands
###########################################################

def test_the_home_directory_is_the_users(connection, monkeypatch):
    monkeypatch.setattr(connection_local.runtime, "get_home_directory", lambda: "/home/someone")

    assert connection.get_home_directory() == "/home/someone"


def test_output_is_decoded_and_trimmed(connection, spawned):
    spawned.output = b"  hello\n"

    assert connection.run_output(["echo", "hello"]) == "hello"


def test_standard_error_is_left_out_by_default(connection, spawned):
    connection.run_output(["echo"])

    assert "stderr" not in only(spawned.calls, None)


def test_standard_error_can_be_included(connection, spawned):
    connection.options.include_stderr = True

    connection.run_output(["echo"])

    assert only(spawned.calls, None)["stderr"] == FakeProcesses.STDOUT


def test_a_command_runs_with_the_connections_options(connection, spawned):
    connection.options.cwd = "/srv"
    connection.options.env = {"JOYBOX_TEST": "value"}

    connection.run_output(["pwd"])
    call = only(spawned.calls, None)

    assert (call["cwd"], call["env"], call["check"]) == ("/srv", {"JOYBOX_TEST": "value"}, False)


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_shell_command_is_run_as_one_string(connection, spawned, method):
    connection.options.shell = True

    getattr(connection, method)(["echo", "one two"])
    call = only(spawned.calls, None)

    assert call["cmd"] == "echo 'one two'"
    assert call["shell"] is True


def test_a_shell_string_reaches_the_shell_verbatim(connection, spawned):
    connection.options.shell = True

    connection.run_output("echo one | tr o 0; exit 4")

    assert only(spawned.calls, None)["cmd"] == "echo one | tr o 0; exit 4"


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_sudo_command_is_prefixed(connection, spawned, monkeypatch, method):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)

    getattr(connection, method)(["id"], sudo = True)

    assert only(spawned.calls, None)["cmd"] == ["sudo", "id"]


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_verbose_command_is_logged(connection, spawned, logged, method):
    connection.flags.verbose = True

    getattr(connection, method)(["echo", "hi"])

    assert logged == ['Running "echo hi"']


@pytest.mark.parametrize("method,failed", [
    ("run_output", ""), ("run_return_code", 1), ("run_blocking", 1)])
def test_a_command_that_cannot_start_reports_failure(connection, spawned, method, failed):
    spawned.error = FileNotFoundError("definitely-not-a-real-binary")

    assert getattr(connection, method)(["definitely-not-a-real-binary"]) == failed


@pytest.mark.parametrize("method", ["run_output", "run_return_code", "run_blocking"])
def test_a_command_that_cannot_start_can_quit_the_program(strict, spawned, logged, method):
    spawned.error = FileNotFoundError("definitely-not-a-real-binary")

    with pytest.raises(SystemExit):
        getattr(strict, method)(["definitely-not-a-real-binary"])
    assert logged == ["definitely-not-a-real-binary"]


def test_a_failing_command_reports_its_code(connection, spawned):
    spawned.code = 3

    assert connection.run_return_code(["false"]) == 3


def test_output_and_errors_can_be_redirected_to_files(connection, spawned, tmp_path):
    connection.options.stdout = str(tmp_path / "out.log")
    connection.options.stderr = str(tmp_path / "err.log")

    assert connection.run_return_code(["echo"]) == 0
    assert (tmp_path / "out.log").read_text() == "stdout\n"
    assert (tmp_path / "err.log").read_text() == "stderr\n"


def test_redirect_files_are_closed_when_the_command_cannot_start(connection, spawned, tmp_path):
    connection.options.stdout = str(tmp_path / "out.log")
    spawned.error = OSError("no exec")

    assert connection.run_return_code(["echo"]) == 1
    assert spawned.calls[0]["stdout"].closed


def test_unredirected_output_is_inherited(connection, spawned):
    connection.run_return_code(["echo"])
    call = only(spawned.calls, None)

    assert (call["stdout"], call["stderr"]) == (None, None)


def test_blocking_output_is_streamed(connection, spawned, monkeypatch):
    streamed = []
    monkeypatch.setattr(connection_local.logger, "log_output", lambda text: None)
    monkeypatch.setattr(connection_local.logger, "record_output", streamed.append)
    spawned.chunks = [b"first\nsec", b"ond\n"]
    spawned.code = 4

    assert connection.run_blocking(["build"]) == 4
    assert streamed == ["first", "second"]


def test_pretending_runs_nothing(pretending, spawned):
    assert pretending.run_return_code(["sh", "-c", "exit 3"]) == 0
    assert pretending.run_output(["echo", "hello"]) == ""
    assert pretending.run_blocking(["echo", "hello"]) == 0
    assert spawned.calls == []


def test_a_checked_command_that_fails_quits_the_program(connection, monkeypatch):
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    with pytest.raises(SystemExit):
        connection.run_checked(["false"])


def test_a_checked_command_can_raise_instead(connection, monkeypatch):
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    with pytest.raises(ValueError):
        connection.run_checked(["false"], throw_exception = True)


def test_a_checked_command_that_succeeds_returns(connection, spawned):
    assert connection.run_checked(["true"]) is None


def test_an_interactive_command_blocks(connection, spawned):
    spawned.code = 4

    assert connection.run_interactive(["sh"]) == 4
