# Imports
import contextlib
import pytest

# Local imports
from joybox.bootstrap import provision
from fakes import RecordingConnection
from provision_helpers import World, build, server


###########################################################
# Workstation checks
###########################################################

def test_an_answering_port_is_open(monkeypatch):
    seen = []
    monkeypatch.setattr(provision.socket, "create_connection",
                        lambda address, timeout: seen.append((address, timeout)) or contextlib.nullcontext())

    assert provision.is_port_open("192.168.122.10", 22) is True
    assert seen == [(("192.168.122.10", 22), 3)]


def test_a_refused_port_is_closed(monkeypatch):
    def refuse(address, timeout):
        raise ConnectionRefusedError()
    monkeypatch.setattr(provision.socket, "create_connection", refuse)

    assert provision.is_port_open("192.168.122.10", 22) is False


def mkcert(monkeypatch, runnable = True, output = ""):
    monkeypatch.setattr(provision.command, "is_runnable_command", lambda cmd: runnable)
    monkeypatch.setattr(provision.command, "run_output_command", lambda **kwargs: output)


def test_mkcert_missing_is_not_ready(monkeypatch):
    mkcert(monkeypatch, runnable = False)

    assert provision.is_mkcert_ready() is False


def test_mkcert_with_a_trusted_root_is_ready(monkeypatch, tmp_path):
    (tmp_path / "rootCA.pem").write_text("ca")
    mkcert(monkeypatch, output = ("%s\n" % tmp_path).encode())

    assert provision.is_mkcert_ready() is True


@pytest.mark.parametrize("output", ["", None, "/nonexistent/caroot"])
def test_mkcert_without_a_root_is_not_ready(monkeypatch, output):
    mkcert(monkeypatch, output = output)

    assert provision.is_mkcert_ready() is False


###########################################################
# Connections
###########################################################

def test_a_connection_never_exits_the_process(entry, monkeypatch):
    built = []
    monkeypatch.setattr(provision, "ConnectionSSH", lambda **kwargs: built.append(kwargs) or kwargs)
    flags = provision.runoptions.RunFlags(exit_on_failure = True)
    provisioner = provision.Provisioner(server = server(), flags = flags)

    provisioner.build_connection("deploy")

    assert built[0]["ssh_host"] == "192.168.122.10"
    assert built[0]["ssh_port"] == 22
    assert built[0]["ssh_user"] == "deploy"
    assert built[0]["ssh_key_filepath"] == "/home/deploy/.ssh/id_ed25519"
    assert built[0]["flags"].exit_on_failure is False
    assert flags.exit_on_failure is True


def test_waiting_for_a_login_gives_up_at_the_deadline(entry, monkeypatch):
    monkeypatch.setattr(provision.time, "sleep", lambda seconds: pytest.fail("slept past the deadline"))

    assert build(World({"root": False})).wait_for_login("root", deadline = -1) is False


###########################################################
# Target helpers
###########################################################

def test_a_secret_is_not_written_when_its_file_cannot_be_made(entry):
    connection = RecordingConnection(return_codes = {"/dev/null": 1})

    assert build(World({})).put_secret(connection, "/root/s", "x") is False
    assert connection.called("write_file") == []


def test_scripts_are_not_shipped_without_a_directory(entry):
    connection = RecordingConnection(return_codes = {"install -d": 1})

    assert build(World({})).push_day0_scripts(connection) is None
    assert connection.called("transfer_files") == []


def test_a_failed_copy_stops_the_shipping(entry):
    class Refusing(RecordingConnection):
        def transfer_files(self, src, dest, excludes = [], sudo = False):
            super().transfer_files(src, dest, excludes = excludes, sudo = sudo)
            return False
    connection = Refusing()

    assert build(World({})).push_day0_scripts(connection) is None
    assert len(connection.called("transfer_files")) == 1


def test_nothing_to_remove_runs_nothing(entry):
    connection = RecordingConnection()
    build(World({})).remove_day0_scripts(connection, None)

    assert connection.commands == []
