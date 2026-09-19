# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox import platform_info


###########################################################
# Platform detection
#
# Drives which binary is launched, whether wine or sandboxie wraps a command,
# and which branch of every per-platform config is read.
###########################################################

def test_exactly_one_platform_matches():
    matched = [
        platform_info.is_windows_platform(),
        platform_info.is_linux_platform(),
        platform_info.is_mac_platform(),
    ]

    assert sum(1 for entry in matched if entry) == 1


def test_the_current_platform_matches_its_predicate():
    current = platform_info.get_current_platform()

    assert current in ["windows", "linux", "macos"]
    assert {
        "windows": platform_info.is_windows_platform,
        "linux": platform_info.is_linux_platform,
        "macos": platform_info.is_mac_platform,
    }[current]() is True


def test_unix_covers_linux_and_mac():
    assert platform_info.is_unix_platform() == (
        platform_info.is_linux_platform() or platform_info.is_mac_platform())


def test_windows_is_not_unix():
    if platform_info.is_windows_platform():
        assert platform_info.is_unix_platform() is False


###########################################################
# Sandboxing
###########################################################

def test_wine_and_sandboxie_are_mutually_exclusive():
    # A command is wrapped by one or the other, never both.
    assert not (platform_info.is_wine_platform() and platform_info.is_sandboxie_platform())


def test_wine_is_the_linux_wrapper():
    assert platform_info.is_wine_platform() == platform_info.is_linux_platform()


def test_sandboxie_is_the_windows_wrapper():
    assert platform_info.is_sandboxie_platform() == platform_info.is_windows_platform()


def test_a_sandbox_exists_on_every_supported_platform():
    if platform_info.is_mac_platform():
        pytest.skip("macos has neither wrapper")

    assert platform_info.is_wine_platform() or platform_info.is_sandboxie_platform()


###########################################################
# Platform reporting
###########################################################

def test_each_predicate_follows_sys_platform(monkeypatch):
    # The predicates read sys.platform directly, so they track it exactly.
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_info.is_windows_platform() is True
    assert platform_info.is_linux_platform() is False
    assert platform_info.get_current_platform() == "windows"

    monkeypatch.setattr(sys, "platform", "linux")
    assert platform_info.is_linux_platform() is True
    assert platform_info.get_current_platform() == "linux"

    monkeypatch.setattr(sys, "platform", "darwin")
    assert platform_info.is_mac_platform() is True
    assert platform_info.get_current_platform() == "macos"


def test_an_unknown_platform_reports_nothing(monkeypatch):
    monkeypatch.setattr(sys, "platform", "sunos5")

    assert platform_info.get_current_platform() is None


def test_a_platform_prefix_is_enough(monkeypatch):
    # sys.platform has carried version suffixes historically.
    monkeypatch.setattr(sys, "platform", "linux2")

    assert platform_info.is_linux_platform() is True


###########################################################
# Linux distribution
###########################################################

def test_distribution_fields_are_strings():
    for accessor in [platform_info.get_linux_distro_name,
                     platform_info.get_linux_distro_version,
                     platform_info.get_linux_distro_id,
                     platform_info.get_linux_distro_id_like,
                     platform_info.get_ubuntu_codename]:
        assert isinstance(accessor(), str)


def test_an_unknown_field_is_empty():
    assert platform_info.get_linux_distro_value("NOT_A_REAL_FIELD") == ""


def test_the_distribution_is_named_on_linux():
    if not platform_info.is_linux_platform():
        pytest.skip("not running on linux")

    assert platform_info.get_linux_distro_name()


def test_ubuntu_detection_agrees_with_the_release_fields():
    expected = any("ubuntu" in value.lower() for value in [
        platform_info.get_linux_distro_name(),
        platform_info.get_linux_distro_id(),
        platform_info.get_linux_distro_id_like(),
    ])

    assert platform_info.is_ubuntu_distro() == expected


def test_values_are_unquoted():
    # os-release quotes values; a stray quote would break a version compare.
    for accessor in [platform_info.get_linux_distro_name,
                     platform_info.get_linux_distro_version]:
        assert '"' not in accessor()
