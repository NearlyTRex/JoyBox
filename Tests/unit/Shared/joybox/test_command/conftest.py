# Third-party imports
import pytest


@pytest.fixture
def logged(monkeypatch):
    from command_helpers import LogRecorder
    return LogRecorder(monkeypatch)
