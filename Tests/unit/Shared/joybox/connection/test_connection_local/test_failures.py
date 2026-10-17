# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.connection import connection_local
from connection_local_helpers import SUDO_OPERATIONS, only


###########################################################
# Privileged failures and dry runs
###########################################################

@pytest.mark.parametrize("method,args", SUDO_OPERATIONS)
def test_a_verbose_privileged_operation_is_logged(connection, recorded, logged, on_linux, monkeypatch, method, args):
    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    connection.flags.verbose = True

    getattr(connection, method)(*args, sudo = True)

    assert logged


@pytest.mark.parametrize("method,args", SUDO_OPERATIONS)
def test_pretending_runs_no_privileged_command(pretending, spawned, on_linux, method, args):
    result = getattr(pretending, method)(*args, sudo = True)

    assert result is (None if method == "read_file" else True)
    assert spawned.calls == []


@pytest.mark.parametrize("method,args", [op for op in SUDO_OPERATIONS if op[0] not in ("write_file", "read_file", "transfer_files")])
def test_a_failed_privileged_command_is_reported(connection, on_linux, monkeypatch, tmp_path, method, args):
    # A failure is the caller's to handle unless the connection exits on failure.
    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    assert getattr(connection, method)(*args, sudo = True) is False


@pytest.mark.parametrize("method,args", [op for op in SUDO_OPERATIONS if op[0] not in ("read_file",)])
def test_a_failed_privileged_command_can_quit_the_program(strict, on_linux, logged, monkeypatch, method, args):
    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    monkeypatch.setattr(strict, "run_blocking", lambda cmd, sudo = False: 1)
    monkeypatch.setattr(strict, "run_return_code", lambda cmd, sudo = False: 1)
    monkeypatch.setattr(connection_local.os.path, "isdir", lambda path: False)

    with pytest.raises(SystemExit):
        getattr(strict, method)(*args, sudo = True)


@pytest.mark.parametrize("method,args", [("change_owner", ("/opt/a", "app:app")), ("change_permission", ("/opt/a", "750"))])
def test_an_unprivileged_ownership_change_runs_as_the_user(connection, recorded, on_linux, method, args):
    getattr(connection, method)(*args)

    assert only(recorded)["sudo"] is False


def test_a_privileged_write_that_cannot_stage_is_reported(connection, recorded, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("no space")
    monkeypatch.setattr(connection_local.tempfile, "mkstemp", refuse)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False
    assert recorded == []


def test_a_privileged_write_cleans_up_when_the_copy_cannot_start(connection, monkeypatch):
    staged = []

    def run(cmd, sudo = False):
        staged.append(cmd[1])
        raise OSError("no exec")

    monkeypatch.setattr(connection, "run_return_code", run)

    assert connection.write_file("/etc/app.conf", "contents", sudo = True) is False
    assert not os.path.exists(staged[0])


def test_a_failed_privileged_download_leaves_no_staged_file(connection, recorded, monkeypatch):
    fetched = []
    monkeypatch.setattr(
        connection_local.network, "download_url",
        lambda url, output_file, **kwargs: fetched.append(output_file) and False)

    assert connection.download_file("https://example.test/a", "/opt/a", sudo = True) is False
    assert not os.path.exists(fetched[0])


def test_a_failed_privileged_move_leaves_no_staged_download(connection, monkeypatch):
    fetched = []
    monkeypatch.setattr(
        connection_local.network, "download_url",
        lambda url, output_file, **kwargs: fetched.append(output_file) or True)
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 1)

    assert connection.download_file("https://example.test/a", "/opt/a", sudo = True) is False
    assert not os.path.exists(fetched[0])


def test_a_privileged_download_is_moved_out_of_staging(connection, monkeypatch):
    moved = []

    def move(cmd, sudo = False, throw_exception = False):
        if cmd[0] == "/bin/mv":
            moved.append(cmd[1])
            os.remove(cmd[1])

    monkeypatch.setattr(connection_local.network, "download_url", lambda url, output_file, **kwargs: True)
    monkeypatch.setattr(connection, "run_checked", move)

    assert connection.download_file("https://example.test/a", "/opt/a", sudo = True) is True
    assert len(moved) == 1
    assert not os.path.exists(moved[0])


def test_a_failed_privileged_file_transfer_is_reported(connection, monkeypatch, tmp_path):
    source = tmp_path / "app.conf"
    source.write_text("KEY=value")
    monkeypatch.setattr(connection, "run_return_code", lambda cmd, sudo = False: 1)

    assert connection.transfer_files(str(source), "/etc/app.conf", sudo = True) is False


def test_a_privileged_transfer_that_cannot_stage_is_reported(connection, recorded, monkeypatch, tmp_path):
    monkeypatch.setattr(connection_local.fileops, "copy_file_or_directory", lambda *args, **kwargs: False)

    assert connection.transfer_files(str(tmp_path), "/opt/app", sudo = True) is False
    assert recorded == []


@pytest.mark.parametrize("failing", ["/bin/mkdir", "/bin/cp"])
def test_a_failed_privileged_transfer_step_is_reported(connection, monkeypatch, tmp_path, failing):
    ran = []

    def run(cmd, sudo = False):
        ran.append(cmd[0])
        return 1 if cmd[0] == failing else 0

    monkeypatch.setattr(connection, "run_return_code", run)

    assert connection.transfer_files(str(tmp_path), "/opt/app", sudo = True) is False
    assert ran[-1] == failing


def test_a_privileged_transfer_that_raises_is_reported(connection, monkeypatch, tmp_path):
    def refuse(*args, **kwargs):
        raise OSError("no space")
    monkeypatch.setattr(connection_local.tempfile, "mkdtemp", refuse)

    assert connection.transfer_files(str(tmp_path), "/opt/app", sudo = True) is False


def test_a_verbose_existence_check_is_logged(connection, logged, tmp_path):
    connection.flags.verbose = True

    connection.does_file_or_directory_exist(str(tmp_path))

    assert logged == ["Checking existence of %s" % tmp_path]


def test_an_existence_check_that_raises_is_reported(connection, monkeypatch):
    def refuse(path):
        raise OSError("denied")
    monkeypatch.setattr(connection_local.os.path, "exists", refuse)

    assert connection.does_file_or_directory_exist("/opt/app") is False


def test_a_file_is_read(connection, logged, tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("data")
    connection.flags.verbose = True

    assert connection.read_file(str(target)) == "data"
    assert logged == ["Reading file %s" % target]
