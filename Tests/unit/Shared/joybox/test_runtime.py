# Imports
import os
import time
import pytest

# Local imports
from joybox import runtime


###########################################################
# Program control and paths
#
# Small enough that the risk is in the details: a quit that does not quit, or
# a directory built against the wrong home.
###########################################################

@pytest.fixture
def home(tmp_path, monkeypatch):
    target = tmp_path / "home"
    target.mkdir()
    monkeypatch.setenv("HOME", str(target))
    monkeypatch.setenv("USERPROFILE", str(target))
    return target


###########################################################
# Quitting
###########################################################

def test_quitting_raises_system_exit():
    with pytest.raises(SystemExit):
        runtime.quit_program()


def test_quitting_defaults_to_a_failure_code():
    # Callers use it to abort, so a zero exit would read as success.
    with pytest.raises(SystemExit) as caught:
        runtime.quit_program()

    assert caught.value.code != 0


@pytest.mark.parametrize("code", [0, 1, 2, 130])
def test_an_exit_code_is_carried_through(code):
    with pytest.raises(SystemExit) as caught:
        runtime.quit_program(code)

    assert caught.value.code == code


###########################################################
# Sleeping
###########################################################

def test_sleeping_waits(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", slept.append)
    runtime.sleep_program(2.5)

    assert slept == [2.5]


def test_sleeping_for_nothing_is_allowed(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", slept.append)
    runtime.sleep_program(0)

    assert slept == [0]


###########################################################
# Time
###########################################################

def test_the_current_time_is_a_float(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1234.75)

    assert runtime.get_current_time() == 1234.75


def test_the_current_timestamp_is_a_whole_number(monkeypatch):
    # It ends up in filenames, where a decimal point is noise.
    monkeypatch.setattr(time, "time", lambda: 1234.75)

    assert runtime.get_current_timestamp() == 1234
    assert isinstance(runtime.get_current_timestamp(), int)


def test_the_timestamp_truncates_rather_than_rounds(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1234.99)

    assert runtime.get_current_timestamp() == 1234


def test_the_time_advances(monkeypatch):
    clock = {"now": 100.0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])
    first = runtime.get_current_time()
    clock["now"] = 200.0

    assert runtime.get_current_time() > first


###########################################################
# Directories
###########################################################

def test_the_home_directory_is_the_users(home):
    assert runtime.get_home_directory() == str(home)


def test_the_home_directory_is_absolute(home):
    assert os.path.isabs(runtime.get_home_directory())


def test_the_cookie_directory_sits_under_the_home(home):
    assert runtime.get_cookie_directory() == os.path.join(str(home), "Cookies")


def test_the_log_directory_sits_under_the_home(home):
    assert runtime.get_log_directory() == os.path.join(str(home), "Logs")


def test_the_cookie_and_log_directories_are_distinct(home):
    assert runtime.get_cookie_directory() != runtime.get_log_directory()


def test_the_directories_follow_the_home(tmp_path, monkeypatch):
    # Nothing is resolved at import time, so a changed home takes effect.
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    monkeypatch.setenv("HOME", str(first))
    monkeypatch.setenv("USERPROFILE", str(first))
    before = runtime.get_log_directory()

    monkeypatch.setenv("HOME", str(second))
    monkeypatch.setenv("USERPROFILE", str(second))
    assert runtime.get_log_directory() != before
