# Imports
import fnmatch
import os

# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import complete_profile, seed_for


###########################################################
# The cloud-init seed
###########################################################

def test_a_key_only_account_is_locked_rather_than_passwordless():
    # An empty password field is not a login nobody can use, it is a login
    # that takes no password at all, which is a console anyone in the room
    # can walk up to.
    _, seed = seed_for(password_hash = "", ssh_keys = ["ssh-ed25519 AAAA"])

    assert seed["autoinstall"]["identity"]["password"] == autoinstall.locked_password


def test_a_configured_password_hash_is_used_as_it_is():
    _, seed = seed_for(password_hash = "$6$rounds=656000$abc$def")

    assert seed["autoinstall"]["identity"]["password"] == "$6$rounds=656000$abc$def"


def test_the_seed_is_a_cloud_config_document():
    # cloud-init ignores a file that does not start with this line.
    text, _ = seed_for()

    assert text.startswith("#cloud-config\n")


def test_the_seed_declares_its_version():
    _, data = seed_for()

    assert data["autoinstall"]["version"] == 1


def test_the_identity_comes_from_the_profile():
    _, data = seed_for(username = "homelab", hostname = "testbox")
    identity = data["autoinstall"]["identity"]

    assert identity["username"] == "homelab"
    assert identity["hostname"] == "testbox"


def test_the_password_hash_survives_unchanged():
    # The hash is full of characters yaml would otherwise reinterpret.
    hashed = "$6$rounds=656000$5dOE1Ns/he7g3InW$4zvSAVoxIvEeyg1"
    _, data = seed_for(password_hash = hashed)

    assert data["autoinstall"]["identity"]["password"] == hashed


def test_an_ssh_key_reaches_the_account():
    _, data = seed_for(ssh_keys = ["ssh-ed25519 AAAA homelab@example.test"])
    account = data["autoinstall"]["user-data"]["users"][0]

    assert account["ssh_authorized_keys"] == ["ssh-ed25519 AAAA homelab@example.test"]


def test_an_account_without_a_key_declares_none():
    _, data = seed_for(ssh_keys = [])
    account = data["autoinstall"]["user-data"]["users"][0]

    assert "ssh_authorized_keys" not in account


def test_the_account_can_use_sudo_without_a_password():
    # Nothing is watching the console to type one.
    _, data = seed_for()
    account = data["autoinstall"]["user-data"]["users"][0]

    assert "NOPASSWD" in account["sudo"]


def test_password_logins_are_turned_off():
    _, data = seed_for()

    assert data["autoinstall"]["ssh"]["allow-pw"] is False
    assert data["autoinstall"]["ssh"]["install-server"] is True


def test_the_profile_account_is_the_only_one():
    # cloud-init's "default" entry would add an ubuntu user with passwordless sudo.
    _, data = seed_for(username = "homelab")

    assert [user["name"] for user in data["autoinstall"]["user-data"]["users"]] == ["homelab"]


def sshd_settings(data):
    files = {entry["path"]: entry["content"] for entry in data["autoinstall"]["user-data"]["write_files"]}
    return dict(line.split(" ", 1) for line in files[autoinstall.sshd_config_path].splitlines())


def test_sshd_takes_only_a_key_for_the_profile_account():
    _, data = seed_for(username = "homelab")
    settings = sshd_settings(data)

    assert settings["PasswordAuthentication"] == "no"
    assert settings["KbdInteractiveAuthentication"] == "no"
    assert settings["PermitRootLogin"] == "no"
    assert settings["AllowUsers"] == "homelab"


def test_sshd_forwards_only_local_ports():
    # A tunnel to a service bound to localhost needs local forwarding; nothing else does.
    settings = sshd_settings(seed_for()[1])

    assert settings["AllowTcpForwarding"] == "local"
    assert settings["X11Forwarding"] == "no"
    assert settings["AllowAgentForwarding"] == "no"


def test_sshd_settings_sort_before_cloud_inits():
    # sshd keeps the first value it reads, and cloud-init writes 50-cloud-init.conf.
    assert os.path.basename(autoinstall.sshd_config_path) < "50-cloud-init.conf"


def test_ssh_is_enabled_on_the_installed_machine():
    # Without this the machine finishes installing and cannot be reached.
    _, data = seed_for()

    assert any("systemctl enable ssh" in step
               for step in data["autoinstall"]["late-commands"])


def test_requested_packages_are_installed():
    _, data = seed_for(packages = ["qemu-guest-agent"])

    assert data["autoinstall"]["packages"] == ["qemu-guest-agent"]


def test_no_packages_declares_none():
    _, data = seed_for(packages = [])

    assert "packages" not in data["autoinstall"]


def test_the_disk_is_partitioned_for_uefi_and_bios():
    # A fixed efi-only partition list fails at grub on a machine booted in
    # legacy BIOS mode; the installer's layout picks the boot partition itself.
    _, data = seed_for()
    storage = data["autoinstall"]["storage"]

    assert "config" not in storage
    assert storage["layout"]["name"] == "direct"


@pytest.mark.parametrize("port", ["enp3s0", "enp5s0", "eno1", "eth0"])
def test_every_wired_port_gets_an_address(port):
    # A port renamed by a card moving slots is still matched.
    _, data = seed_for()
    ethernets = data["autoinstall"]["network"]["ethernets"].values()

    assert any(
        fnmatch.fnmatch(port, entry["match"]["name"]) and entry["dhcp4"]
        for entry in ethernets)


def test_an_unplugged_port_does_not_hold_up_the_boot():
    _, data = seed_for()

    assert all(entry["optional"] for entry in data["autoinstall"]["network"]["ethernets"].values())


def test_the_machine_powers_off_when_it_is_done():
    # A reboot with the stick still in boots the installer and starts over.
    _, data = seed_for()

    assert data["autoinstall"]["shutdown"] == "poweroff"


def test_the_largest_disk_is_the_one_installed_to():
    _, data = seed_for()

    assert data["autoinstall"]["storage"]["layout"]["match"] == {"size": "largest"}


def test_the_instance_metadata_names_the_host():
    meta = autoinstall.build_meta_data(complete_profile(hostname = "testbox"))

    assert "instance-id: autoinstall" in meta
    assert "local-hostname: testbox" in meta
