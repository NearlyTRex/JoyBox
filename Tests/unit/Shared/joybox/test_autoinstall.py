# Third-party imports
import pytest

# Local imports
from joybox import autoinstall


###########################################################
# Choosing a release
#
# The build takes whatever the release page lists as newest. Picking the
# wrong entry installs an older point release, which is a different kernel
# than the one the profile was written against.
###########################################################

def listing_with(*images):
    return "".join('<a href="%s">%s</a>\n' % (image, image) for image in images)


def image_named(version):
    return "ubuntu-%s-live-server-amd64.iso" % version


@pytest.fixture
def release_page(monkeypatch):
    state = {"html": ""}
    monkeypatch.setattr(
        autoinstall.network, "get_remote_html", lambda **kwargs: state["html"])
    return state


def test_a_release_listing_is_addressed_by_version():
    assert autoinstall.get_release_listing_url("24.04") == \
        "https://releases.ubuntu.com/24.04/"


def test_the_published_images_are_found(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04.2"))

    assert autoinstall.find_release_images("24.04") == [
        image_named("24.04.1"), image_named("24.04.2")]


def test_an_image_listed_twice_is_returned_once(release_page):
    # The page links each image more than once.
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04.1"))

    assert autoinstall.find_release_images("24.04") == [image_named("24.04.1")]


def test_the_newest_point_release_is_taken(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04.3"))

    assert autoinstall.find_latest_release_image("24.04") == image_named("24.04.3")


def test_point_releases_are_ordered_as_numbers(release_page):
    # Sorted as text, 24.04.10 comes before 24.04.2 and the build silently
    # installs an older release.
    release_page["html"] = listing_with(image_named("24.04.2"), image_named("24.04.10"))

    assert autoinstall.find_latest_release_image("24.04") == image_named("24.04.10")


def test_a_release_with_no_point_release_is_ordered_first(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04"))

    assert autoinstall.find_latest_release_image("24.04") == image_named("24.04.1")


def test_a_desktop_image_is_not_taken_for_a_server_one(release_page):
    release_page["html"] = listing_with(
        "ubuntu-24.04.1-desktop-amd64.iso", image_named("24.04.1"))

    assert autoinstall.find_release_images("24.04") == [image_named("24.04.1")]


def test_the_download_url_is_under_its_release(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"))

    assert autoinstall.find_latest_release_url("24.04") == \
        "https://releases.ubuntu.com/24.04/" + image_named("24.04.1")


def test_a_page_with_no_images_finds_nothing(release_page):
    release_page["html"] = "<html><body>nothing here</body></html>"

    assert autoinstall.find_release_images("24.04") == []
    assert autoinstall.find_latest_release_image("24.04") is None
    assert autoinstall.find_latest_release_url("24.04") is None


def test_a_page_that_could_not_be_fetched_finds_nothing(release_page):
    release_page["html"] = None

    assert autoinstall.find_release_images("24.04") == []


@pytest.mark.parametrize("image,expected", [
    (image_named("24.04"), (24, 4)),
    (image_named("24.04.1"), (24, 4, 1)),
    ("not-an-image.iso", ()),
])
def test_an_image_version_is_read_as_numbers(image, expected):
    assert autoinstall.get_image_version(image) == expected


###########################################################
# The install profile
###########################################################

def complete_profile(**overrides):
    profile = {
        "version": "24.04",
        "username": "operator",
        "hostname": "testbox",
        "password_hash": "$6$rounds=656000$abc$def",
        "ssh_keys": [],
    }
    profile.update(overrides)
    return profile


def test_a_profile_with_a_password_is_complete():
    assert autoinstall.is_install_profile_complete(complete_profile()) is True


def test_a_profile_with_only_a_key_is_complete():
    # Password login is turned off in the seed, so a key is the usual setup.
    profile = complete_profile(password_hash = "", ssh_keys = ["ssh-ed25519 AAAA"])

    assert autoinstall.is_install_profile_complete(profile) is True


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
    isolated_settings.set_value("UserData.Autoinstall", "autoinstall_username", "operator")
    isolated_settings.set_value("UserData.Autoinstall", "autoinstall_hostname", "testbox")
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_ssh_keys", "ssh-ed25519 AAAA,ssh-rsa BBBB")

    profile = autoinstall.get_install_profile()

    assert profile["username"] == "operator"
    assert profile["hostname"] == "testbox"
    assert profile["ssh_keys"] == ["ssh-ed25519 AAAA", "ssh-rsa BBBB"]


def test_an_unconfigured_profile_is_incomplete(isolated_settings):
    # Nothing is hardcoded, so a fresh machine has to be told who to create.
    assert autoinstall.is_install_profile_complete(
        autoinstall.get_install_profile()) is False


###########################################################
# The cloud-init seed
###########################################################

def seed_for(**overrides):
    import yaml

    text = autoinstall.build_user_data(complete_profile(**overrides))
    return text, yaml.safe_load(text)


def test_the_seed_is_a_cloud_config_document():
    # cloud-init ignores a file that does not start with this line.
    text, _ = seed_for()

    assert text.startswith("#cloud-config\n")


def test_the_seed_declares_its_version():
    _, data = seed_for()

    assert data["autoinstall"]["version"] == 1


def test_the_identity_comes_from_the_profile():
    _, data = seed_for(username = "operator", hostname = "testbox")
    identity = data["autoinstall"]["identity"]

    assert identity["username"] == "operator"
    assert identity["hostname"] == "testbox"


def test_the_password_hash_survives_unchanged():
    # The hash is full of characters yaml would otherwise reinterpret.
    hashed = "$6$rounds=656000$5dOE1Ns/he7g3InW$4zvSAVoxIvEeyg1"
    _, data = seed_for(password_hash = hashed)

    assert data["autoinstall"]["identity"]["password"] == hashed


def test_an_ssh_key_reaches_the_account():
    _, data = seed_for(ssh_keys = ["ssh-ed25519 AAAA operator@example.test"])
    account = data["autoinstall"]["user-data"]["users"][1]

    assert account["ssh_authorized_keys"] == ["ssh-ed25519 AAAA operator@example.test"]


def test_an_account_without_a_key_declares_none():
    _, data = seed_for(ssh_keys = [])
    account = data["autoinstall"]["user-data"]["users"][1]

    assert "ssh_authorized_keys" not in account


def test_the_account_can_use_sudo_without_a_password():
    # Nothing is watching the console to type one.
    _, data = seed_for()
    account = data["autoinstall"]["user-data"]["users"][1]

    assert "NOPASSWD" in account["sudo"]


def test_password_logins_are_turned_off():
    _, data = seed_for()

    assert data["autoinstall"]["ssh"]["allow-pw"] is False
    assert data["autoinstall"]["ssh"]["install-server"] is True


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
    # A root partition alone leaves a machine that installs and will not boot.
    _, data = seed_for()
    entries = data["autoinstall"]["storage"]["config"]
    mounts = {entry["path"] for entry in entries if entry["type"] == "mount"}

    assert mounts == {"/", "/boot/efi"}


def test_the_existing_contents_are_replaced():
    _, data = seed_for()
    disk = data["autoinstall"]["storage"]["config"][0]

    assert disk["preserve"] is False
    assert disk["ptable"] == "gpt"


def test_the_instance_metadata_names_the_host():
    meta = autoinstall.build_meta_data(complete_profile(hostname = "testbox"))

    assert "instance-id: autoinstall" in meta
    assert "local-hostname: testbox" in meta


###########################################################
# Boot configuration
###########################################################

def test_the_installer_is_pointed_at_the_seed():
    arguments = autoinstall.get_kernel_arguments()

    assert "autoinstall" in arguments
    assert "ds=nocloud;s=/cdrom/nocloud/" in arguments


def test_the_serial_console_is_only_added_when_asked():
    assert "console=ttyS0" not in autoinstall.get_kernel_arguments()
    assert "console=ttyS0" in autoinstall.get_kernel_arguments({"serial_console": True})


@pytest.mark.parametrize("line", [
    "\tlinux\t/casper/vmlinuz quiet --- \n",
    "\tlinux\t/casper/vmlinuz quiet ---\n",
    "  append initrd=/casper/initrd quiet ---\n",
])
def test_the_arguments_go_before_the_separator(line):
    # Anything after the separator is passed to the installed system rather
    # than the installer, so it would quietly not autoinstall at all.
    patched = autoinstall.patch_boot_entry(line)

    assert patched.index("autoinstall") < patched.index("---")


def test_a_line_without_a_separator_takes_the_arguments_at_the_end():
    patched = autoinstall.patch_boot_entry("\tlinux\t/casper/vmlinuz quiet\n")

    assert patched.rstrip().endswith("ds=nocloud;s=/cdrom/nocloud/")


def test_a_line_keeps_the_arguments_it_had():
    patched = autoinstall.patch_boot_entry("\tlinux\t/casper/vmlinuz quiet ---\n")

    assert "/casper/vmlinuz" in patched
    assert "quiet" in patched


def test_a_line_already_pointed_at_the_seed_is_left_alone():
    # Building twice from the same tree would otherwise stack the arguments.
    once = autoinstall.patch_boot_entry("\tlinux\t/casper/vmlinuz quiet ---\n")
    twice = autoinstall.patch_boot_entry(once)

    assert once == twice


def test_the_menu_stops_waiting():
    contents = "set default=\"0\"\nset timeout=30\n"

    patched = autoinstall.patch_boot_config_contents(contents)

    assert "set timeout=%d" % autoinstall.boot_timeout in patched
    assert "set timeout=30" not in patched


def test_an_isolinux_menu_stops_waiting():
    # isolinux counts its timeout in tenths of a second.
    patched = autoinstall.patch_boot_config_contents("timeout 300\n")

    assert "timeout %d" % (autoinstall.boot_timeout * 10) in patched


def test_lines_that_are_not_boot_entries_are_untouched():
    contents = "menuentry \"Try or Install Ubuntu Server\" {\n\tset gfxpayload=keep\n}\n"

    assert autoinstall.patch_boot_config_contents(contents) == contents


def test_every_known_boot_configuration_is_looked_for():
    found = autoinstall.get_boot_config_files("/iso")

    assert any(path.endswith("grub.cfg") for path in found)
    assert any(path.endswith("loopback.cfg") for path in found)
    assert any(path.endswith("txt.cfg") for path in found)
