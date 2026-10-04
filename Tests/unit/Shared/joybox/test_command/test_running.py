# Imports
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import command


###########################################################
# Running commands
#
# run_command is the one place every wrapper launches a child process. What
# it captures, logs and writes, and what it waits for afterwards, decides what
# every caller sees.
###########################################################

def run(cmd = None, **kwargs):
    return command.run_command(cmd or ["/usr/bin/tool", "--flag"], **kwargs)


###########################################################
# Pretend runs
###########################################################

def test_a_pretend_run_launches_nothing(processes):
    assert run(pretend_run = True) == ("", 0)
    assert processes.launched == []
    assert processes.called == []


def test_a_missing_options_object_falls_back_to_defaults(processes):
    processes.stdout = "out\n"

    assert run(options = None) == ("out", 0)


###########################################################
# Captured output
###########################################################

def test_the_output_and_return_code_are_returned(processes):
    processes.stdout = "first\nsecond\n"
    processes.returncode = 3

    assert run() == ("first\nsecond", 3)


def test_the_command_is_launched_as_a_list(processes):
    run("/usr/bin/tool --flag")

    assert processes.only().cmd == ["/usr/bin/tool", "--flag"]


def test_output_is_not_kept_when_capture_is_off(processes):
    processes.stdout = "first\n"

    assert run(capture_output = False) == ("", 0)


def test_stdout_lines_are_logged_when_asked(processes, logged):
    processes.stdout = "first\nsecond\n"

    run(log_stdout = True)

    assert logged.info == ["first", "second"]


def test_stdout_is_not_logged_by_default(processes, logged):
    processes.stdout = "first\n"

    run()

    assert logged.info == []


def test_reading_stops_at_the_end_of_the_stream(processes):
    # A child that closes stdout and keeps running must not spin the reader.
    processes.stdout = "first\n"
    processes.never_exits = True

    assert run() == ("first", 0)
    assert processes.only().poll_calls == 0


def test_the_working_directory_and_environment_are_passed(processes):
    options = command.create_command_options(cwd = "/work")
    options.set_env_var("JOYBOX_TEST", "1")

    run(options = options)

    kwargs = processes.only().kwargs
    assert kwargs["cwd"] == "/work"
    assert kwargs["env"]["JOYBOX_TEST"] == "1"
    assert kwargs["shell"] is False


def test_a_shell_command_is_launched_as_one_string(processes):
    options = command.create_command_options(is_shell = True)

    run(["echo", "a b"], options = options)

    proc = processes.only()
    assert isinstance(proc.cmd, str)
    assert proc.kwargs["shell"] is True


def test_a_verbose_run_prints_the_command(processes, monkeypatch):
    printed = []
    monkeypatch.setattr(command, "print_command", lambda cmd: printed.append(cmd))

    run(verbose = True)

    assert printed == [["/usr/bin/tool", "--flag"]]


###########################################################
# Standard error
###########################################################

def test_stdin_is_not_piped_by_default(processes):
    run()

    assert processes.only().kwargs["stdin"] is None


def test_stdin_input_is_written_to_the_process_and_closed(processes):
    # Secrets go in this way so they never appear in argv or the logged command.
    options = command.create_command_options(stdin_input = "secret")

    run(options = options)

    stdin = processes.only().stdin
    assert processes.only().kwargs["stdin"] == subprocess.PIPE
    assert stdin.written == "secret"
    assert stdin.closed is True


def test_a_process_that_ignores_stdin_still_runs(processes):
    processes.stdin_broken = True
    processes.stdout = "out\n"
    options = command.create_command_options(stdin_input = "secret")

    assert run(options = options) == ("out", 0)


def test_stderr_goes_to_the_terminal_by_default(processes):
    processes.stderr = "warning\n"

    assert run() == ("", 0)
    assert processes.only().kwargs["stderr"] is None


def test_included_stderr_is_merged_into_the_output(processes):
    processes.stdout = "out\n"
    processes.stderr = "err\n"
    options = command.create_command_options(include_stderr = True)

    output, _ = run(options = options)

    assert processes.only().kwargs["stderr"] == subprocess.STDOUT
    assert output == "out\nerr"


def test_included_stderr_is_kept_even_when_it_is_also_logged(processes, logged):
    processes.stderr = "err\n"
    options = command.create_command_options(include_stderr = True)

    output, _ = run(options = options, log_stderr = True)

    assert processes.only().kwargs["stderr"] == subprocess.PIPE
    assert output == "err"
    assert logged.info == ["err"]


def test_logged_stderr_is_not_captured_unless_included(processes, logged):
    processes.stderr = "err\n"

    output, _ = run(log_stderr = True)

    assert output == ""
    assert logged.info == ["err"]


###########################################################
# Output files
###########################################################

def test_stdout_and_stderr_are_written_to_their_files(processes, tmp_path):
    processes.stdout = "out\n"
    processes.stderr = "err\n"
    options = command.create_command_options(
        stdout = str(tmp_path / "out.log"),
        stderr = str(tmp_path / "err.log"))

    output, _ = run(options = options)

    assert (tmp_path / "out.log").read_text() == "out\n"
    assert (tmp_path / "err.log").read_text() == "err\n"
    assert output == "out"


def test_an_output_file_is_closed_when_the_launch_fails(processes, tmp_path, monkeypatch):
    opened = []
    real_open = open

    def tracking_open(*args, **kwargs):
        handle = real_open(*args, **kwargs)
        opened.append(handle)
        return handle

    monkeypatch.setattr("builtins.open", tracking_open)
    processes.error = OSError("no such program")
    options = command.create_command_options(stdout = str(tmp_path / "out.log"))

    assert run(options = options) == ("", 1)
    assert opened and all(handle.closed for handle in opened)


###########################################################
# After the run
###########################################################

def test_blocking_processes_are_waited_for_before_postprocessing(processes):
    options = command.create_command_options(blocking_processes = ["wineserver"])

    run(options = options)

    assert processes.waited_for == [["wineserver"]]
    assert processes.events[-2:] == ["blocking", "postprocess"]


def test_no_blocking_processes_means_no_wait(processes):
    run()

    assert processes.waited_for == []


def test_the_run_is_postprocessed(processes):
    run(verbose = False, exit_on_failure = True)

    assert len(processes.postprocessed) == 1
    assert processes.postprocessed[0]["kwargs"]["exit_on_failure"] is True


def test_a_run_without_processing_is_neither_pre_nor_postprocessed(processes, monkeypatch):
    def fail(**kwargs):
        raise AssertionError("processing was turned off")

    monkeypatch.setattr(command, "preprocess_command", fail)
    options = command.create_command_options(allow_processing = False)

    run(options = options)

    assert processes.postprocessed == []


def test_the_preprocessed_command_is_what_runs(processes, monkeypatch):
    monkeypatch.setattr(
        command, "preprocess_command",
        lambda cmd, options, **kwargs: (["wine"] + cmd, options))

    run(["/games/Game.exe"])

    assert processes.only().cmd == ["wine", "/games/Game.exe"]


###########################################################
# Passthrough, daemon and suppressed runs
###########################################################

def test_a_passthrough_run_inherits_the_terminal(processes):
    processes.returncode = 4
    options = command.create_command_options(passthrough = True, cwd = "/work")

    assert run(options = options) == ("", 4)
    assert processes.launched == []
    assert processes.called[0]["kwargs"]["cwd"] == "/work"


def test_a_passthrough_run_is_finished_like_any_other(processes):
    options = command.create_command_options(passthrough = True, blocking_processes = ["wineserver"])

    run(options = options)

    assert processes.waited_for == [["wineserver"]]
    assert len(processes.postprocessed) == 1


def test_a_daemon_is_detached_and_not_waited_for(processes):
    options = command.create_command_options(is_daemon = True, blocking_processes = ["wineserver"])

    assert run(options = options) == ("", 0)

    kwargs = processes.only().kwargs
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["start_new_session"] is True
    assert "wait" not in processes.events
    assert processes.slept == [0.5]


def test_a_daemon_is_not_cleaned_up_after_launch(processes):
    # Postprocessing kills the wine server and moves output files, which
    # would take a still-running daemon down with it.
    options = command.create_command_options(is_daemon = True)

    run(options = options)

    assert processes.postprocessed == []
    assert processes.waited_for == []


def test_a_daemon_keeps_its_creation_flags(processes):
    options = command.create_command_options(is_daemon = True, creationflags = 8)

    run(options = options)

    assert processes.only().kwargs["creationflags"] & 8


def test_a_suppressed_run_discards_both_streams(processes):
    processes.returncode = 2
    options = command.create_command_options(
        suppress_output = True, blocking_processes = ["wineserver"])

    assert run(options = options) == ("", 2)

    kwargs = processes.only().kwargs
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert processes.events == ["wait", "blocking", "postprocess"]


###########################################################
# Failures
###########################################################

def test_a_failed_launch_is_a_failed_run(processes, logged):
    processes.error = OSError("no such program")

    assert run() == ("", 1)
    assert logged.errors == []


def test_a_verbose_failed_launch_is_logged(processes, logged):
    processes.error = OSError("no such program")

    run(verbose = True)

    assert len(logged.errors) == 1
    assert logged.quits == [False]


@pytest.mark.parametrize("verbose", [False, True])
def test_a_failed_launch_quits_when_asked_whether_verbose_or_not(processes, logged, verbose):
    processes.error = OSError("no such program")

    run(verbose = verbose, exit_on_failure = True)

    assert logged.quits == [True]


###########################################################
# Wrappers
###########################################################

def test_the_output_wrapper_returns_only_the_output(processes):
    processes.stdout = "value\n"
    processes.returncode = 5

    assert command.run_output_command(["/usr/bin/tool"]) == "value"


def test_the_returncode_wrapper_returns_only_the_code_and_logs_the_streams(processes, logged):
    processes.stdout = "out\n"
    processes.stderr = "err\n"
    processes.returncode = 5

    assert command.run_returncode_command(["/usr/bin/tool"]) == 5
    assert sorted(logged.info) == ["err", "out"]


@pytest.mark.parametrize("wrapper", [command.run_output_command, command.run_returncode_command])
def test_the_wrappers_pass_the_run_flags_through(monkeypatch, wrapper):
    seen = {}

    def run_command(cmd, **kwargs):
        seen.update(kwargs)
        return ("", 0)

    monkeypatch.setattr(command, "run_command", run_command)

    wrapper(["/usr/bin/tool"], verbose = True, pretend_run = True, exit_on_failure = True)

    assert seen["verbose"] is True
    assert seen["pretend_run"] is True
    assert seen["exit_on_failure"] is True
