# Imports
import signal
import sys
import types
import pytest

# Local imports
from joybox import process


###########################################################
# Process management
#
# Used to stop an emulator before touching its save files. Matching the wrong
# process kills something unrelated; matching none leaves a file open while it
# is copied.
###########################################################

class FakeProcess:

    def __init__(self, name, pid = 1000, running = True):
        self._name = name
        self.pid = pid
        self.running = running
        self.killed = False
        self.signals = []

    def name(self):
        return self._name

    def kill(self):
        self.killed = True
        self.running = False

    def send_signal(self, number):
        self.signals.append(number)

    def is_running(self):
        return self.running


class FakeError(Exception):
    pass


@pytest.fixture
def psutil(monkeypatch):
    state = {"processes": [], "raise_on_iter": None}

    module = types.ModuleType("psutil")
    module.NoSuchProcess = type("NoSuchProcess", (FakeError,), {})
    module.AccessDenied = type("AccessDenied", (FakeError,), {})
    module.ZombieProcess = type("ZombieProcess", (FakeError,), {})

    def process_iter():
        if state["raise_on_iter"]:
            raise state["raise_on_iter"]
        return list(state["processes"])

    module.process_iter = process_iter
    monkeypatch.setitem(sys.modules, "psutil", module)
    state["module"] = module
    return state


def names(found):
    return sorted(entry.name() for entry in found)


###########################################################
# Finding
###########################################################

def test_a_process_is_found_by_name(psutil):
    psutil["processes"] = [FakeProcess("dolphin"), FakeProcess("firefox")]

    assert names(process.find_active_named_processes(["dolphin"])) == ["dolphin"]


def test_several_names_are_matched(psutil):
    psutil["processes"] = [FakeProcess("dolphin"), FakeProcess("cemu"), FakeProcess("firefox")]

    assert names(process.find_active_named_processes(["dolphin", "cemu"])) == \
        ["cemu", "dolphin"]


def test_an_absent_process_is_not_found(psutil):
    psutil["processes"] = [FakeProcess("firefox")]

    assert process.find_active_named_processes(["dolphin"]) == []


def test_no_names_match_nothing(psutil):
    psutil["processes"] = [FakeProcess("dolphin")]

    assert process.find_active_named_processes([]) == []


def test_no_running_processes_match_nothing(psutil):
    assert process.find_active_named_processes(["dolphin"]) == []


def test_a_full_path_matches_by_its_basename(psutil):
    # Blocking processes are recorded as program paths, and psutil reports the
    # executable name alone.
    psutil["processes"] = [FakeProcess("Dolphin.AppImage")]
    found = process.find_active_named_processes(["/home/user/Emulators/Dolphin.AppImage"])

    assert names(found) == ["Dolphin.AppImage"]


def test_a_windows_path_matches_by_its_basename(psutil):
    # ntpath is used so a windows style path splits on either separator.
    psutil["processes"] = [FakeProcess("dolphin.exe")]
    found = process.find_active_named_processes(["C:\\Emulators\\Dolphin\\dolphin.exe"])

    assert names(found) == ["dolphin.exe"]


def test_a_matching_name_is_not_reported_twice(psutil):
    # An exact match also matches on basename; reporting both would kill it
    # twice and log a spurious error.
    psutil["processes"] = [FakeProcess("dolphin")]
    found = process.find_active_named_processes(["dolphin"])

    assert len(found) == 1


def test_a_partial_name_does_not_match(psutil):
    psutil["processes"] = [FakeProcess("dolphin-emu")]

    assert process.find_active_named_processes(["dolphin"]) == []


def test_an_inaccessible_process_list_matches_nothing(psutil):
    psutil["raise_on_iter"] = psutil["module"].AccessDenied()

    assert process.find_active_named_processes(["dolphin"]) == []


def test_a_vanished_process_list_matches_nothing(psutil):
    psutil["raise_on_iter"] = psutil["module"].NoSuchProcess()

    assert process.find_active_named_processes(["dolphin"]) == []


###########################################################
# Killing
###########################################################

def test_a_matching_process_is_killed(psutil):
    target = FakeProcess("dolphin")
    psutil["processes"] = [target]
    process.kill_active_named_processes(["dolphin"])

    assert target.killed is True


def test_an_unmatched_process_is_left_running(psutil):
    # Killing the wrong process is the failure that matters here.
    other = FakeProcess("firefox")
    psutil["processes"] = [FakeProcess("dolphin"), other]
    process.kill_active_named_processes(["dolphin"])

    assert other.killed is False


def test_killing_nothing_is_harmless(psutil):
    process.kill_active_named_processes(["dolphin"])


def test_every_match_is_killed(psutil):
    first = FakeProcess("dolphin", pid = 1)
    second = FakeProcess("dolphin", pid = 2)
    psutil["processes"] = [first, second]
    process.kill_active_named_processes(["dolphin"])

    assert first.killed and second.killed


def test_a_denied_kill_is_logged_not_raised(psutil, monkeypatch):
    errors = []
    monkeypatch.setattr(process.logger, "log_error", errors.append)

    class Stubborn(FakeProcess):
        def kill(self):
            raise psutil["module"].AccessDenied()

    psutil["processes"] = [Stubborn("dolphin")]
    process.kill_active_named_processes(["dolphin"])

    assert errors


###########################################################
# Interrupting
###########################################################

def test_a_matching_process_is_interrupted(psutil):
    target = FakeProcess("dolphin")
    psutil["processes"] = [target]
    process.interrupt_active_named_processes(["dolphin"])

    assert target.signals


def test_the_platform_interrupt_signal_is_used(psutil):
    expected = signal.CTRL_C_EVENT if hasattr(signal, "CTRL_C_EVENT") else signal.SIGINT
    target = FakeProcess("dolphin")
    psutil["processes"] = [target]
    process.interrupt_active_named_processes(["dolphin"])

    assert target.signals == [expected]


def test_an_interrupt_does_not_kill(psutil):
    # Interrupting gives the emulator a chance to flush its saves.
    target = FakeProcess("dolphin")
    psutil["processes"] = [target]
    process.interrupt_active_named_processes(["dolphin"])

    assert target.killed is False


def test_an_unmatched_process_is_not_interrupted(psutil):
    other = FakeProcess("firefox")
    psutil["processes"] = [FakeProcess("dolphin"), other]
    process.interrupt_active_named_processes(["dolphin"])

    assert other.signals == []


def test_interrupting_nothing_is_harmless(psutil):
    process.interrupt_active_named_processes(["dolphin"])


def test_a_denied_interrupt_is_logged_not_raised(psutil, monkeypatch):
    errors = []
    monkeypatch.setattr(process.logger, "log_error", errors.append)

    class Stubborn(FakeProcess):
        def send_signal(self, number):
            raise psutil["module"].AccessDenied()

    psutil["processes"] = [Stubborn("dolphin")]
    process.interrupt_active_named_processes(["dolphin"])

    assert errors


###########################################################
# Waiting
###########################################################

@pytest.fixture
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(process.runtime, "sleep_program", slept.append)
    monkeypatch.setattr(process.logger, "log_info", lambda message: None)
    monkeypatch.setattr(process.logger, "log_warning", lambda message: None)
    return slept


def test_waiting_returns_once_a_process_finishes(psutil, no_sleep):
    class Finishing(FakeProcess):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.checks = 0

        def is_running(self):
            self.checks += 1
            return self.checks < 3

    target = Finishing("dolphin")
    psutil["processes"] = [target]
    process.wait_for_named_processes(["dolphin"])

    assert target.checks == 3


def test_waiting_for_nothing_returns_at_once(psutil, no_sleep):
    process.wait_for_named_processes(["dolphin"])

    assert no_sleep == []


def test_a_finished_process_is_not_waited_on(psutil, no_sleep):
    psutil["processes"] = [FakeProcess("dolphin", running = False)]
    process.wait_for_named_processes(["dolphin"])

    assert no_sleep == []


def test_waiting_gives_up_at_the_timeout(psutil, no_sleep, monkeypatch):
    # Without this a hung emulator blocks the whole save sync.
    clock = {"now": 0.0}
    monkeypatch.setattr(process.time, "time", lambda: clock["now"])
    monkeypatch.setattr(
        process.runtime, "sleep_program",
        lambda seconds: clock.__setitem__("now", clock["now"] + 1))

    psutil["processes"] = [FakeProcess("dolphin")]
    process.wait_for_named_processes(["dolphin"], timeout = 5)

    assert clock["now"] >= 5


def test_no_timeout_is_not_an_immediate_give_up(psutil, monkeypatch):
    clock = {"now": 0.0}
    checks = {"count": 0}
    monkeypatch.setattr(process.time, "time", lambda: clock["now"])
    monkeypatch.setattr(process.logger, "log_info", lambda message: None)

    class Finishing(FakeProcess):
        def is_running(self):
            checks["count"] += 1
            return checks["count"] < 4

    monkeypatch.setattr(
        process.runtime, "sleep_program",
        lambda seconds: clock.__setitem__("now", clock["now"] + 10000))

    psutil["processes"] = [Finishing("dolphin")]
    process.wait_for_named_processes(["dolphin"], timeout = 0)

    assert checks["count"] == 4


def test_a_vanished_process_ends_the_wait(psutil, no_sleep):
    class Vanishing(FakeProcess):
        def is_running(self):
            raise psutil["module"].NoSuchProcess()

    psutil["processes"] = [Vanishing("dolphin")]
    process.wait_for_named_processes(["dolphin"])


def test_a_denied_wait_is_reported_not_raised(psutil, monkeypatch):
    warnings = []
    monkeypatch.setattr(process.logger, "log_warning", warnings.append)
    monkeypatch.setattr(process.logger, "log_info", lambda message: None)

    class Denied(FakeProcess):
        def is_running(self):
            raise psutil["module"].AccessDenied()

    psutil["processes"] = [Denied("dolphin")]
    process.wait_for_named_processes(["dolphin"])

    assert warnings
