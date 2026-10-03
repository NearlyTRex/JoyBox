# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox.connection import connection_ssh
from fakes import FakeSSHClient, FakeSFTP
from connection_ssh_helpers import build, logged, RefusingClient, AcceptingClient, fake_paramiko


###########################################################
# Connecting
#
# Provisioning asks whether a login works as a normal question - root on a
# hardened server is refused by design - so probing must not raise or log.
###########################################################


def test_a_refused_login_is_an_answer_not_an_error(monkeypatch):
    fake_paramiko(monkeypatch, RefusingClient())
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


def test_paramiko_is_imported_on_first_use(monkeypatch):
    module = object()
    monkeypatch.setattr(connection_ssh, "paramiko", None)
    monkeypatch.setitem(sys.modules, "paramiko", module)

    connection_ssh._ensure_paramiko()

    assert connection_ssh.paramiko is module


def test_a_login_without_any_credential_is_refused(monkeypatch):
    fake_paramiko(monkeypatch, AcceptingClient())
    connection = build()
    connection.ssh_password = None

    with pytest.raises(ValueError):
        connection.connect()


def test_a_key_login_offers_only_that_key(monkeypatch):
    client = fake_paramiko(monkeypatch, AcceptingClient())
    loaded = []
    monkeypatch.setattr(connection_ssh, "_load_private_key",
        lambda filepath = None, key_str = None: loaded.append((filepath, key_str)) or "key")
    connection = build()
    connection.ssh_key_filepath = "/keys/id"
    connection.ssh_key_str = "inline"

    connection.connect()
    options = client.connects[0][1]

    assert loaded == [(None, "inline")]
    assert (options["pkey"], options["allow_agent"], options["look_for_keys"]) == ("key", False, False)


def test_a_key_file_is_loaded_when_no_key_text_is_given(monkeypatch):
    fake_paramiko(monkeypatch, AcceptingClient())
    loaded = []
    monkeypatch.setattr(connection_ssh, "_load_private_key",
        lambda filepath = None, key_str = None: loaded.append((filepath, key_str)) or "key")
    connection = build()
    connection.ssh_key_filepath = "/keys/id"

    connection.connect()

    assert loaded == [("/keys/id", None)]


def key_class(name, accepts):
    class Key:
        @staticmethod
        def from_private_key_file(path):
            if not accepts:
                raise ValueError("not %s" % name)
            return (name, path)

        @staticmethod
        def from_private_key(handle):
            if not accepts:
                raise ValueError("not %s" % name)
            return (name, handle.read())
    Key.__name__ = name
    return Key


def key_module(monkeypatch, accepting, from_path = None):
    pkey = type("PKey", (), {"from_path": staticmethod(from_path)} if from_path else {})
    classes = {name: key_class(name, name == accepting) for name in ["Ed25519Key", "ECDSAKey", "RSAKey"]}
    fake_paramiko(monkeypatch, None, PKey = pkey, **classes)


def test_a_key_file_type_is_sniffed_when_paramiko_can(monkeypatch):
    key_module(monkeypatch, None, from_path = lambda path: ("sniffed", path))

    assert connection_ssh._load_private_key(filepath = "/keys/id") == ("sniffed", "/keys/id")


def test_a_key_file_falls_back_through_the_key_types(monkeypatch):
    key_module(monkeypatch, "ECDSAKey")

    assert connection_ssh._load_private_key(filepath = "/keys/id") == ("ECDSAKey", "/keys/id")


def test_key_text_is_loaded_without_a_file(monkeypatch):
    key_module(monkeypatch, "RSAKey", from_path = lambda path: ("sniffed", path))

    assert connection_ssh._load_private_key(key_str = "PEM") == ("RSAKey", "PEM")


def test_an_unreadable_key_names_every_attempt(monkeypatch):
    key_module(monkeypatch, None)

    with pytest.raises(ValueError, match = "Ed25519Key.*ECDSAKey.*RSAKey"):
        connection_ssh._load_private_key(key_str = "garbage")


def test_setup_connects(monkeypatch):
    client = fake_paramiko(monkeypatch, AcceptingClient())
    build().setup()

    assert client.connected


def test_a_failed_setup_is_logged_and_raised(monkeypatch):
    fake_paramiko(monkeypatch, RefusingClient())
    lines = logged(monkeypatch)

    with pytest.raises(PermissionError):
        build().setup()
    assert lines == ["SSH connection failed", "Authentication failed."]


def test_nothing_is_connected_without_a_client():
    assert build().is_connected() is False


def test_a_failed_close_is_logged_and_the_client_dropped(monkeypatch):
    class Unclosable(FakeSSHClient):
        def close(self):
            raise OSError("broken pipe")
    lines = logged(monkeypatch)

    build(Unclosable()).teardown()

    assert lines == ["Failed to close SSH connection", "broken pipe"]
    assert connection_ssh.ConnectionSSH.ssh_client is None


def test_an_unresolvable_remote_home_is_none():
    class Broken(FakeSFTP):
        def normalize(self, path):
            raise OSError("denied")
    sftp = Broken()

    assert build(FakeSSHClient(sftp = sftp)).get_home_directory() is None
    assert sftp.closed


def test_teardown_without_a_client_does_nothing():
    build().teardown()

    assert connection_ssh.ConnectionSSH.ssh_client is None
