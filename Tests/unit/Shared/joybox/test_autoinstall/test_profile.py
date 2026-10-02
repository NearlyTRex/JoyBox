# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import complete_profile


###########################################################
# The install profile
###########################################################

def test_a_profile_with_a_password_is_complete():
    assert autoinstall.is_install_profile_complete(complete_profile()) is True


def test_a_profile_with_only_a_key_is_complete():
    # Password login is turned off in the seed, so a key is the usual setup.
    profile = complete_profile(password_hash = "", ssh_keys = ["ssh-ed25519 AAAA"])

    assert autoinstall.is_install_profile_complete(profile) is True


@pytest.mark.parametrize("name", ["operator", "admin", "root", "backup", "sudo"])
def test_a_reserved_username_is_refused(name):
    # The installer refuses these, but only once it is already running on the
    # target machine, where it drops to a shell and waits.
    profile = complete_profile(username = name)

    assert autoinstall.is_install_profile_complete(profile) is False
    assert any(
        name in problem for problem in autoinstall.get_install_profile_problems(profile))


@pytest.mark.parametrize("name", ["Homelab", "9llm", "has space", "UPPER"])
def test_a_username_the_installer_will_not_accept_is_refused(name):
    assert autoinstall.is_install_profile_complete(complete_profile(username = name)) is False


@pytest.mark.parametrize("name", ["homelab", "llm-box", "gpu_server", "_svc"])
def test_an_ordinary_username_is_accepted(name):
    assert autoinstall.is_install_profile_complete(complete_profile(username = name)) is True


def test_the_reserved_list_is_the_one_the_installer_uses():
    # Sourced from usr/lib/user-setup/reserved-usernames in the installer
    # squashfs; a short list here would let a refused name through.
    assert "operator" in autoinstall.reserved_usernames
    assert "admin" in autoinstall.reserved_usernames
    assert len(autoinstall.reserved_usernames) > 100


def test_a_profile_with_no_way_in_is_incomplete():
    # The installed machine would be unreachable, and nobody is at the
    # keyboard to notice.
    profile = complete_profile(password_hash = "", ssh_keys = [])

    assert autoinstall.is_install_profile_complete(profile) is False
    assert autoinstall.get_install_profile_problems(profile)


@pytest.mark.parametrize("field", ["username", "hostname"])
def test_a_profile_missing_an_answer_is_incomplete(field):
    profile = complete_profile(**{field: ""})

    assert autoinstall.is_install_profile_complete(profile) is False
    assert any(field in problem for problem in autoinstall.get_install_profile_problems(profile))


@pytest.mark.parametrize("candidate", [None, "", [], "a profile"])
def test_something_that_is_not_a_profile_is_incomplete(candidate):
    assert autoinstall.is_install_profile_complete(candidate) is False
    assert autoinstall.get_install_profile_problems(candidate)


def test_a_complete_profile_has_nothing_to_report():
    assert autoinstall.get_install_profile_problems(complete_profile()) == []


def test_a_profile_is_read_from_settings(isolated_settings):
    isolated_settings.set_value("UserData.Autoinstall", "autoinstall_username", "homelab")
    isolated_settings.set_value("UserData.Autoinstall", "autoinstall_hostname", "testbox")
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_ssh_keys", "ssh-ed25519 AAAA,ssh-rsa BBBB")

    profile = autoinstall.get_install_profile()

    assert profile["username"] == "homelab"
    assert profile["hostname"] == "testbox"
    assert profile["ssh_keys"] == ["ssh-ed25519 AAAA", "ssh-rsa BBBB"]


def test_spaces_after_commas_are_not_part_of_the_value(isolated_settings):
    # An ini is written by hand, so the space after a comma is expected.
    # Carrying it through hands apt a package named " git" and puts a key with
    # a leading space in authorized_keys, on a machine nobody is watching.
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_packages", "curl, git, nvtop")
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_ssh_keys", "ssh-ed25519 AAAA, ssh-rsa BBBB")

    profile = autoinstall.get_install_profile()

    assert profile["packages"] == ["curl", "git", "nvtop"]
    assert profile["ssh_keys"] == ["ssh-ed25519 AAAA", "ssh-rsa BBBB"]


def test_an_empty_entry_in_a_list_is_dropped(isolated_settings):
    # A trailing comma is easy to leave behind, and an empty package name
    # fails the whole apt-get install it lands in.
    isolated_settings.set_value("UserData.Autoinstall", "autoinstall_packages", "curl,,git,")

    assert autoinstall.get_install_profile()["packages"] == ["curl", "git"]


def test_an_unconfigured_profile_is_incomplete(isolated_settings):
    # Nothing is hardcoded, so a fresh machine has to be told who to create.
    assert autoinstall.is_install_profile_complete(
        autoinstall.get_install_profile()) is False
