# Imports
import sys
import types

import pytest

# Local imports
from joybox import permissions, platform_info


###########################################################
# Root detection and elevation
#
# Windows goes through pyuac when it is installed; elsewhere the uid decides.
###########################################################

def fake_pyuac(monkeypatch, admin):
    module = types.SimpleNamespace(elevations = 0)
    module.isUserAdmin = lambda: admin

    def run_as_admin():
        module.elevations += 1
    module.runAsAdmin = run_as_admin
    monkeypatch.setitem(sys.modules, "pyuac", module)
    return module


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(platform_info, "is_windows_platform", lambda: True)


@pytest.fixture
def posix(monkeypatch):
    monkeypatch.setattr(platform_info, "is_windows_platform", lambda: False)


@pytest.mark.parametrize("uid, expected", [(0, True), (1000, False)])
def test_posix_root_is_uid_zero(posix, monkeypatch, uid, expected):
    monkeypatch.setattr(permissions.os, "getuid", lambda: uid, raising = False)

    assert permissions.is_user_root() is expected


@pytest.mark.parametrize("admin", [True, False])
def test_windows_root_asks_pyuac(windows, monkeypatch, admin):
    fake_pyuac(monkeypatch, admin)

    assert permissions.is_user_root() is admin


def test_windows_without_pyuac_is_not_root(windows, monkeypatch):
    monkeypatch.setitem(sys.modules, "pyuac", None)

    assert permissions.is_user_root() is False


def test_a_non_callable_is_ignored(windows, monkeypatch):
    pyuac = fake_pyuac(monkeypatch, admin = False)

    assert permissions.run_as_root("not callable") is None
    assert pyuac.elevations == 0


def test_windows_admin_runs_the_function(windows, monkeypatch):
    fake_pyuac(monkeypatch, admin = True)
    calls = []

    permissions.run_as_root(lambda: calls.append(1))

    assert calls == [1]


def test_windows_non_admin_elevates_instead_of_running(windows, monkeypatch):
    pyuac = fake_pyuac(monkeypatch, admin = False)
    calls = []

    permissions.run_as_root(lambda: calls.append(1))

    assert calls == []
    assert pyuac.elevations == 1


def test_windows_without_pyuac_runs_the_function(windows, monkeypatch):
    monkeypatch.setitem(sys.modules, "pyuac", None)
    calls = []

    permissions.run_as_root(lambda: calls.append(1))

    assert calls == [1]


def test_a_failing_function_propagates(windows, monkeypatch):
    fake_pyuac(monkeypatch, admin = True)

    def boom():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        permissions.run_as_root(boom)


def test_posix_runs_the_function(posix):
    calls = []

    permissions.run_as_root(lambda: calls.append(1))

    assert calls == [1]
