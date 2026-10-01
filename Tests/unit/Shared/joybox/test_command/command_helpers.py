# Imports
import io
import subprocess

# Local imports
from joybox import command


###########################################################
# Process doubles
#
# command.run_* hand everything to subprocess. The doubles stand in for the
# child process so the stream plumbing, return codes and post-run steps can be
# checked without launching anything.
###########################################################

class FakeProcess:

    def __init__(self, owner, cmd, **kwargs):
        self.owner = owner
        self.cmd = cmd
        self.kwargs = kwargs
        self.returncode = owner.returncode
        self.poll_calls = 0
        merged = kwargs.get("stderr") == subprocess.STDOUT
        stdout_text = owner.stdout + (owner.stderr if merged else "")
        self.stdout = io.StringIO(stdout_text) if kwargs.get("stdout") == subprocess.PIPE else None
        self.stderr = io.StringIO(owner.stderr) if kwargs.get("stderr") == subprocess.PIPE else None

    def wait(self):
        self.owner.events.append("wait")
        return self.returncode

    def poll(self):
        self.poll_calls += 1
        return None if self.owner.never_exits else self.returncode


class FakeProcesses:

    def __init__(self, monkeypatch):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 0
        self.never_exits = False
        self.error = None
        self.launched = []
        self.called = []
        self.events = []
        self.waited_for = []
        self.postprocessed = []
        self.slept = []

        def popen(cmd, **kwargs):
            if self.error:
                raise self.error
            proc = FakeProcess(self, cmd, **kwargs)
            self.launched.append(proc)
            return proc

        def call(cmd, **kwargs):
            self.called.append({"cmd": cmd, "kwargs": kwargs})
            return self.returncode

        def postprocess(cmd, options, **kwargs):
            self.events.append("postprocess")
            self.postprocessed.append({"cmd": cmd, "options": options, "kwargs": kwargs})

        def wait_for(names):
            self.events.append("blocking")
            self.waited_for.append(list(names))

        monkeypatch.setattr(command.subprocess, "Popen", popen)
        monkeypatch.setattr(command.subprocess, "call", call)
        monkeypatch.setattr(command, "postprocess_command", postprocess)
        monkeypatch.setattr(command.process, "wait_for_named_processes", wait_for)
        monkeypatch.setattr(command.runtime, "sleep_program", lambda seconds: self.slept.append(seconds))

    # The single launched process, failing loudly when there was not exactly one
    def only(self):
        assert len(self.launched) == 1, self.launched
        return self.launched[0]


###########################################################
# Logger double
###########################################################

class LogRecorder:

    def __init__(self, monkeypatch):
        self.info = []
        self.errors = []
        self.quits = []
        monkeypatch.setattr(command.logger, "log_info", lambda message, *args, **kwargs: self.info.append(message))

        def log_error(message, quit_program = False, **kwargs):
            self.errors.append(message)
            self.quits.append(quit_program)

        monkeypatch.setattr(command.logger, "log_error", log_error)
