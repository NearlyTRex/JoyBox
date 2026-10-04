# Local imports
from joybox import runoptions
from joybox.connection import connection_ssh
from fakes import FakeSSHClient, FakeTransport


def build(client = None, **flag_overrides):
    flags = runoptions.RunFlags(verbose = False, exit_on_failure = False)
    for key, value in flag_overrides.items():
        setattr(flags, key, value)
    connection = connection_ssh.ConnectionSSH(
        ssh_host = "server.test",
        ssh_user = "deploy",
        ssh_password = "unused",
        flags = flags,
        options = runoptions.RunOptions())
    if client is not None:
        connection_ssh.ConnectionSSH.ssh_client = client
    return connection


def logged(monkeypatch):
    lines = []
    monkeypatch.setattr(connection_ssh.logger, "log_info", lambda message, **kwargs: lines.append(message))
    monkeypatch.setattr(connection_ssh.logger, "log_error", lambda message, **kwargs: lines.append(str(message)))
    return lines


class RefusingClient(FakeSSHClient):
    def __init__(self):
        super().__init__()
        self.connects = []

    def set_missing_host_key_policy(self, policy):
        pass

    def get_transport(self):
        return None

    def connect(self, host, **kwargs):
        self.connects.append((host, kwargs))
        raise PermissionError("Authentication failed.")


class AcceptingClient(RefusingClient):
    def __init__(self):
        super().__init__()
        self.connected = False

    def get_transport(self):
        return FakeTransport(active = self.connected)

    def connect(self, host, **kwargs):
        self.connects.append((host, kwargs))
        self.connected = True


def fake_paramiko(monkeypatch, client, **members):
    class Module:
        class AutoAddPolicy:
            pass

        @staticmethod
        def SSHClient():
            return client

    for name, value in members.items():
        setattr(Module, name, value)
    monkeypatch.setattr(connection_ssh, "paramiko", Module)
    return client
