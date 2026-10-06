# Imports
import pytest

# Local imports
from joybox import system


###########################################################
# Program control
###########################################################

@pytest.fixture
def logged(monkeypatch):
    lines = {"info": [], "error": [], "warning": []}
    monkeypatch.setattr(system.logger, "log_info", lines["info"].append)
    monkeypatch.setattr(system.logger, "log_error", lines["error"].append)
    monkeypatch.setattr(system.logger, "log_warning", lines["warning"].append)
    return lines


def test_success_is_logged_and_does_not_exit(logged):
    system.run_main(lambda: True)

    assert logged["info"] == ["Script completed successfully"]


def test_no_result_logs_nothing(logged):
    system.run_main(lambda: None)

    assert logged == {"info": [], "error": [], "warning": []}


def test_failure_exits_nonzero(logged):
    with pytest.raises(SystemExit) as raised:
        system.run_main(lambda: False)

    assert raised.value.code == 1
    assert logged["error"] == ["Script completed with errors"]


def test_an_interrupt_exits_with_the_sigint_status(logged):
    def interrupted():
        raise KeyboardInterrupt

    with pytest.raises(SystemExit) as raised:
        system.run_main(interrupted)

    assert raised.value.code == 130
    assert logged["warning"]


def test_an_exception_is_logged_and_exits_nonzero(logged):
    def broken():
        raise RuntimeError("boom")

    with pytest.raises(SystemExit) as raised:
        system.run_main(broken)

    assert raised.value.code == 1
    assert logged["error"] == ["Script failed with exception: boom"]
