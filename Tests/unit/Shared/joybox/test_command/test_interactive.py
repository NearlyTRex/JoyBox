# Imports
import subprocess
import sys
import threading
import types

# Third-party imports
import pytest

# Local imports
from joybox import command


###########################################################
# Interactive commands
#
# The child gets a pseudo-terminal: its output is echoed live and the user's
# input is forwarded. The terminal, select and the child are all faked, so
# nothing is spawned and no real descriptor is touched.
###########################################################

MASTER_FD = 1001
SLAVE_FD = 1002


class FakeOs:

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.end_of_stream = b""
        self.closed = []
        self.written = []

    def read(self, fd, size):
        if self.chunks:
            return self.chunks.pop(0)
        if isinstance(self.end_of_stream, Exception):
            raise self.end_of_stream
        return self.end_of_stream

    def write(self, fd, data):
        self.written.append((fd, data))
        return len(data)

    def close(self, fd):
        self.closed.append(fd)

    def __getattr__(self, name):
        import os
        return getattr(os, name)


class FakeChild:

    def __init__(self, owner, cmd, **kwargs):
        self.owner = owner
        self.cmd = cmd
        self.kwargs = kwargs
        self.returncode = None
        self.polls_left = owner.polls

    def poll(self):
        if self.polls_left > 0:
            self.polls_left -= 1
            return None
        self.returncode = self.owner.returncode
        return self.returncode

    def terminate(self):
        self.owner.events.append("terminate")

    def wait(self):
        self.owner.events.append("wait")
        self.returncode = -15
        return self.returncode


class ScriptedInput:

    def __init__(self, lines):
        self.lines = list(lines)

    def readline(self):
        return self.lines.pop(0) if self.lines else ""


class Terminal:

    def __init__(self, monkeypatch):
        self.polls = 3
        self.returncode = 0
        self.interrupt = False
        self.error = None
        self.children = []
        self.events = []
        self.waited_for = []
        self.postprocessed = []
        self.os = FakeOs([b"hello\n"])

        def popen(cmd, **kwargs):
            if self.error:
                raise self.error
            child = FakeChild(self, cmd, **kwargs)
            self.children.append(child)
            return child

        # Each source is not ready on its first poll, then always ready
        polled = set()

        def select(rlist, wlist, xlist, timeout):
            if self.interrupt and sys.stdin in rlist:
                raise KeyboardInterrupt()
            if id(rlist[0]) not in polled:
                polled.add(id(rlist[0]))
                return ([], [], [])
            return (rlist, [], [])

        monkeypatch.setitem(sys.modules, "pty", types.SimpleNamespace(openpty = lambda: (MASTER_FD, SLAVE_FD)))
        monkeypatch.setitem(sys.modules, "select", types.SimpleNamespace(select = select))
        monkeypatch.setattr(command, "os", self.os)
        monkeypatch.setattr(command.subprocess, "Popen", popen)
        monkeypatch.setattr(command.platform_info, "is_windows_platform", lambda: False)
        monkeypatch.setattr(sys, "stdin", ScriptedInput(["typed\n"]))
        monkeypatch.setattr(
            command.process, "wait_for_named_processes",
            lambda names: self.waited_for.append(list(names)))
        monkeypatch.setattr(
            command, "postprocess_command",
            lambda cmd, options, **kwargs: self.postprocessed.append(kwargs))

    def only(self):
        assert len(self.children) == 1, self.children
        return self.children[0]


@pytest.fixture
def terminal(monkeypatch):
    return Terminal(monkeypatch)


def run(cmd = None, **kwargs):
    return command.run_interactive_command(cmd or ["/usr/bin/tool"], **kwargs)


###########################################################
# POSIX terminal
###########################################################

def test_a_pretend_interactive_run_launches_nothing(terminal):
    assert run(pretend_run = True) == 0
    assert terminal.children == []


def test_the_child_runs_on_the_pseudo_terminal(terminal):
    run()

    kwargs = terminal.only().kwargs
    assert kwargs["stdin"] == SLAVE_FD
    assert kwargs["stdout"] == SLAVE_FD
    assert kwargs["stderr"] == SLAVE_FD


def test_the_child_return_code_is_returned(terminal):
    terminal.returncode = 7

    assert run() == 7


@pytest.mark.parametrize("end_of_stream", [b"", OSError(5, "Input/output error")])
def test_the_child_output_is_echoed_until_the_terminal_closes(terminal, capsys, end_of_stream):
    # Linux reports a closed terminal as EIO rather than an empty read.
    terminal.os.end_of_stream = end_of_stream

    run()

    assert "hello" in capsys.readouterr().out


def test_user_input_is_forwarded_to_the_child(terminal):
    run()

    assert (MASTER_FD, b"typed\n") in terminal.os.written


def test_both_ends_of_the_terminal_are_closed(terminal):
    run()

    assert sorted(terminal.os.closed) == [MASTER_FD, SLAVE_FD]


def test_the_child_gets_the_working_directory_and_environment(terminal):
    options = command.create_command_options(cwd = "/work")
    options.set_env_var("JOYBOX_TEST", "1")

    run(options = options)

    kwargs = terminal.only().kwargs
    assert kwargs["cwd"] == "/work"
    assert kwargs["env"]["JOYBOX_TEST"] == "1"


def test_a_shell_interactive_command_runs_through_the_shell(terminal):
    options = command.create_command_options(is_shell = True)

    run(["echo", "a b"], options = options)

    child = terminal.only()
    assert isinstance(child.cmd, str)
    assert child.kwargs["shell"] is True


def test_an_interrupt_stops_the_child_and_reports_its_exit(terminal):
    terminal.interrupt = True

    assert run() == -15
    assert terminal.events == ["terminate", "wait"]
    assert MASTER_FD in terminal.os.closed


def test_blocking_processes_are_waited_for_after_an_interactive_run(terminal):
    terminal.returncode = 3
    options = command.create_command_options(blocking_processes = ["wineserver"])

    assert run(options = options) == 3
    assert terminal.waited_for == [["wineserver"]]


def test_an_interactive_run_is_postprocessed_with_the_run_flags(terminal):
    run(exit_on_failure = True)

    assert terminal.postprocessed == [{"verbose": False, "pretend_run": False, "exit_on_failure": True}]


def test_an_interactive_run_without_processing_is_not_postprocessed(terminal, monkeypatch):
    def fail(**kwargs):
        raise AssertionError("processing was turned off")

    monkeypatch.setattr(command, "preprocess_command", fail)
    options = command.create_command_options(allow_processing = False)

    run(options = options)

    assert terminal.postprocessed == []


def test_an_interactive_run_is_preprocessed_and_printed_when_verbose(terminal, monkeypatch):
    printed = []
    monkeypatch.setattr(
        command, "preprocess_command",
        lambda cmd, options, **kwargs: (["wine"] + cmd, options))
    monkeypatch.setattr(command, "print_command", lambda cmd: printed.append(cmd))

    run(["/games/Game.exe"], verbose = True)

    assert terminal.only().cmd == ["wine", "/games/Game.exe"]
    assert printed == [["wine", "/games/Game.exe"]]


def test_a_missing_options_object_falls_back_to_defaults(terminal):
    assert run(options = None) == 0


###########################################################
# Failures
###########################################################

@pytest.fixture
def logged_errors(monkeypatch):
    quits = []
    monkeypatch.setattr(
        command.logger, "log_error",
        lambda message, quit_program = False, **kwargs: quits.append(quit_program))
    return quits


def test_a_failed_check_returns_its_code(terminal, logged_errors):
    terminal.error = subprocess.CalledProcessError(9, ["/usr/bin/tool"])

    assert run() == 9
    assert logged_errors == []


def test_a_failed_launch_returns_one(terminal, logged_errors):
    terminal.error = OSError("no such program")

    assert run() == 1


@pytest.mark.parametrize("error", [subprocess.CalledProcessError(9, ["x"]), OSError("missing")])
@pytest.mark.parametrize("verbose", [False, True])
def test_an_interactive_failure_quits_when_asked_whether_verbose_or_not(terminal, logged_errors, error, verbose):
    terminal.error = error

    run(verbose = verbose, exit_on_failure = True)

    assert logged_errors == [True]


def test_a_verbose_interactive_failure_is_logged(terminal, logged_errors):
    terminal.error = OSError("missing")

    run(verbose = True)

    assert logged_errors == [False]


###########################################################
# Windows terminal
###########################################################

class FakePty:

    instances = None
    read_finished = None

    def __init__(self, cmd, cwd, env):
        self.cmd = cmd
        self.cwd = cwd
        self.env = env
        self.alive = True
        self.written = []
        self.terminated = False
        self.exitstatus = 6
        self.reads = ["", "out"]
        FakePty.instances.append(self)

    @classmethod
    def spawn(cls, cmd, cwd = None, env = None):
        return cls(cmd, cwd, env)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def isalive(self):
        return self.alive

    def read(self, size):
        if self.reads:
            return self.reads.pop(0)
        FakePty.read_finished.set()
        raise EOFError()

    def write(self, data):
        # The child exits on input, but only once its output has been read.
        FakePty.read_finished.wait(timeout = 5)
        self.written.append(data)
        self.alive = False

    def terminate(self):
        self.terminated = True
        self.alive = False


class InterruptingInput:

    def readline(self):
        raise KeyboardInterrupt()


@pytest.fixture
def windows(terminal, monkeypatch):
    FakePty.instances = []
    FakePty.read_finished = threading.Event()
    monkeypatch.setattr(sys, "stdin", ScriptedInput(["", "typed\n"]))
    monkeypatch.setattr(command.platform_info, "is_windows_platform", lambda: True)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_sandboxie", lambda cmd: False)
    monkeypatch.setitem(sys.modules, "winpty", types.SimpleNamespace(PtyProcess = FakePty))
    return FakePty.instances


def test_a_windows_interactive_run_returns_the_exit_status(windows):
    assert run() == 6


def test_a_windows_interactive_run_forwards_input(windows):
    run()

    assert windows[0].written == ["typed\n"]


def test_a_windows_interactive_run_echoes_the_child_output(windows, capsys):
    run()

    assert "out" in capsys.readouterr().out


def test_a_windows_interactive_run_gets_the_working_directory_and_environment(windows):
    options = command.create_command_options(cwd = "C:\\work")
    options.set_env_var("JOYBOX_TEST", "1")

    run(options = options)

    assert windows[0].cwd == "C:\\work"
    assert windows[0].env["JOYBOX_TEST"] == "1"


def test_a_windows_interrupt_terminates_the_child(windows, monkeypatch):
    # Output never ends, so the reader can only stop once the child is gone
    monkeypatch.setattr(FakePty, "read", lambda self, size: "")
    monkeypatch.setattr(sys, "stdin", InterruptingInput())

    run()

    assert windows[0].terminated is True


def test_a_windows_interactive_run_waits_for_blocking_processes(windows, terminal):
    options = command.create_command_options(blocking_processes = ["wineserver"])

    assert run(options = options) == 6
    assert terminal.waited_for == [["wineserver"]]
