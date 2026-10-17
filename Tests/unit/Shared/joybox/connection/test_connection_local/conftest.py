# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from joybox.connection import connection_local

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted,
# so this directory's own conftest cannot shadow the suite's top level one.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def connection():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = False),
        runoptions.RunOptions())


@pytest.fixture
def pretending():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = False, pretend_run = True),
        runoptions.RunOptions())


@pytest.fixture
def recorded(connection, monkeypatch):
    # Stands in for every way this connection runs a command, so the sudo
    # branches can be driven without a root shell.
    calls = []

    def record(name):
        def run(cmd, sudo = False, **kwargs):
            calls.append({"name": name, "cmd": cmd, "sudo": sudo})
            return 0 if name != "run_output" else ""
        return run

    for name in ["run_output", "run_return_code", "run_blocking", "run_checked"]:
        monkeypatch.setattr(connection, name, record(name))
    return calls


@pytest.fixture
def delegated(monkeypatch):
    # Records what the non-sudo paths hand to the shared primitives.
    calls = []

    def record(module, name):
        def run(*args, **kwargs):
            calls.append({"name": name, "args": args, "kwargs": kwargs})
            return True
        monkeypatch.setattr(module, name, run)

    for name in ["copy_file_or_directory", "touch_file", "make_directory",
                 "remove_file_or_directory", "move_file_or_directory", "create_symlink"]:
        record(connection_local.fileops, name)
    record(connection_local.network, "download_url")
    record(connection_local.archive, "extract_archive")
    return calls


@pytest.fixture
def spawned(monkeypatch):
    # Beside this file, so importable only once the path above is set
    from connection_local_helpers import FakeProcesses
    fake = FakeProcesses()
    monkeypatch.setattr(connection_local, "subprocess", fake)
    return fake


@pytest.fixture
def logged(monkeypatch):
    lines = []
    monkeypatch.setattr(connection_local.logger, "log_info", lambda message, **kwargs: lines.append(message))
    monkeypatch.setattr(connection_local.logger, "log_error", lambda message, **kwargs: lines.append(str(message)))
    return lines


@pytest.fixture
def strict():
    return connection_local.ConnectionLocal(
        runoptions.RunFlags(verbose = False, exit_on_failure = True),
        runoptions.RunOptions())


@pytest.fixture
def on_linux(monkeypatch):
    monkeypatch.setattr(connection_local.platform_info, "is_linux_platform", lambda: True)
