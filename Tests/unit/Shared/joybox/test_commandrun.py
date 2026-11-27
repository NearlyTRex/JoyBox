# Third-party imports
import pytest

# Local imports
from joybox import commandbase
from joybox import commandrun


###########################################################
# Running a prepared command
#
# Prefix setup runs its own tools through here, as they are. Nothing may be
# wrapped for a prefix or cleaned up after, and the processes the command
# blocks on are still waited for, or the prefix is used before it is ready.
###########################################################

def test_the_command_runs_as_given(processes):
    processes.stdout = "done\n"

    output, returncode = commandrun.run_prepared_command(
        ["C:/Games/Setup.exe", "/silent"], commandbase.create_command_options())

    assert (output, returncode) == ("done", 0)
    assert processes.only().cmd == ["C:/Games/Setup.exe", "/silent"]
    assert processes.postprocessed == []


def test_blocking_processes_are_waited_for(processes):
    options = commandbase.create_command_options(blocking_processes = ["wineserver"])

    commandrun.run_prepared_command(["/tools/wineboot"], options)

    assert processes.waited_for == [["wineserver"]]


def test_no_blocking_processes_means_no_wait(processes):
    commandrun.wait_for_blocking_processes(commandbase.create_command_options())

    assert processes.waited_for == []


def test_a_daemon_is_not_waited_for(processes):
    options = commandbase.create_command_options(is_daemon = True, blocking_processes = ["wineserver"])

    assert commandrun.run_prepared_command(["/tools/server"], options) == ("", 0)
    assert processes.waited_for == []


###########################################################
# Return codes
###########################################################

def run_for_code(cmd = "/tools/wineboot --init", **kwargs):
    return commandrun.run_prepared_returncode_command(cmd, commandbase.create_command_options(), **kwargs)


def test_the_return_code_is_returned(processes):
    processes.returncode = 3

    assert run_for_code() == 3
    assert processes.only().cmd == ["/tools/wineboot", "--init"]


def test_a_pretend_run_launches_nothing(processes):
    assert run_for_code(pretend_run = True) == 0
    assert processes.launched == []


def test_the_output_is_logged_rather_than_kept(processes, monkeypatch):
    logged = []
    monkeypatch.setattr(commandrun.logger, "log_info", logged.append)
    processes.stdout = "line one\nline two\n"

    run_for_code()

    assert logged == ["line one", "line two"]


def test_a_command_that_cannot_start_fails_quietly(processes, monkeypatch):
    errors = []
    monkeypatch.setattr(commandrun.logger, "log_error", lambda message, **kwargs: errors.append(message))
    processes.error = FileNotFoundError("no wineboot")

    assert run_for_code() == 1
    assert errors == []


@pytest.mark.parametrize("flags", [{"verbose": True}, {"exit_on_failure": True}])
def test_a_command_that_cannot_start_is_reported_when_asked(processes, monkeypatch, flags):
    errors = []
    monkeypatch.setattr(commandrun.logger, "log_error",
                        lambda message, quit_program = False: errors.append((str(message), quit_program)))
    processes.error = FileNotFoundError("no wineboot")

    assert run_for_code(**flags) == 1
    assert errors == [("no wineboot", flags.get("exit_on_failure", False))]
