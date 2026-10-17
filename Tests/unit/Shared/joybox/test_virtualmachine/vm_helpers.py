# Local imports
from joybox import virtualmachine

NAME = "joybox-test"


def fake_connection(monkeypatch, **kwargs):
    from fakes import RecordingConnection
    connection = RecordingConnection(**kwargs)
    monkeypatch.setattr(virtualmachine, "get_local_connection", lambda *a, **k: connection)
    return connection
