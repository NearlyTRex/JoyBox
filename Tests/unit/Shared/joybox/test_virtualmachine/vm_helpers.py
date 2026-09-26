# Local imports
from joybox import virtualmachine

NAME = "joybox-test"


def record(monkeypatch, returncode = 0, output = ""):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, returncode = returncode, output = output)


def fake_connection(monkeypatch, **kwargs):
    from fakes import RecordingConnection
    connection = RecordingConnection(**kwargs)
    monkeypatch.setattr(virtualmachine, "get_local_connection", lambda *a, **k: connection)
    return connection
