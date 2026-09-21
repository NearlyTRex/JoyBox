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


###########################################################
# Verifying the download
#
# The image arrives over the network and is then booted on a machine that
# installs itself from it. A truncated or substituted image is only noticed
# once it is already running, so it is checked first.
###########################################################

CHECKSUM = "9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a522657b6d34a0c4e6c"


def checksum_listing(*entries):
    return "".join("%s *%s\n" % (checksum, name) for checksum, name in entries)


def test_the_checksums_are_published_beside_the_images():
    assert autoinstall.get_checksum_listing_url("24.04") == \
        "https://releases.ubuntu.com/24.04/SHA256SUMS"


def test_a_published_checksum_is_read():
    listing = checksum_listing((CHECKSUM, image_named("24.04.1")))

    assert autoinstall.parse_checksum_listing(listing) == {
        image_named("24.04.1"): CHECKSUM}


def test_a_checksum_is_matched_to_its_own_image():
    # The listing covers every image published for the release.
    listing = checksum_listing(
        ("0" * 64, "ubuntu-24.04.1-desktop-amd64.iso"),
        (CHECKSUM, image_named("24.04.1")))

    checksums = autoinstall.parse_checksum_listing(listing)

    assert checksums[image_named("24.04.1")] == CHECKSUM


@pytest.mark.parametrize("listing", [
    "",
    None,
    "not a checksum listing",
    "tooshort *ubuntu-24.04.1-live-server-amd64.iso",
])
def test_an_unusable_checksum_listing_reads_as_nothing(listing):
    assert autoinstall.parse_checksum_listing(listing) == {}


@pytest.fixture
def published_checksum(monkeypatch):
    # The listing is fetched and its signature checked before any of it is
    # believed, so this stands in for the whole of that.
    state = {"checksums": {image_named("24.04.1"): CHECKSUM}}
    monkeypatch.setattr(
        autoinstall, "fetch_release_checksums", lambda **kwargs: state["checksums"])
    return state


def test_a_matching_image_verifies(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: CHECKSUM)

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is True


def test_a_checksum_comparison_ignores_case(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: CHECKSUM.upper())

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is True


def test_an_image_that_does_not_match_is_refused(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: "0" * 64)

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is False


def test_an_image_with_no_published_checksum_is_refused(published_checksum, tmp_path):
    # Nothing to compare against is not the same as a match.
    published_checksum["checksums"] = {"something-else.iso": CHECKSUM}
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is False


def test_an_unreadable_image_is_refused(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: None)

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is False


###########################################################
# Who signed the checksums
#
# A checksum fetched over the same connection as the image proves only that
# the two agree. The signature over it is what ties the image back to the
# people who published it, so it is checked against a key obtained some other
# way rather than one fetched alongside.
###########################################################

UBUNTU_FINGERPRINT = "843938DF228D22F7B3742BC0D94AA3F0EFE21092"


def status_line(fingerprint = UBUNTU_FINGERPRINT):
    return "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG %s 2026-09-15 1789499472 0 4 0 1 10 00 %s\n" % (
        fingerprint, fingerprint)


@pytest.fixture
def signature_check(monkeypatch, tmp_path):
    # A keyring on disk, and whatever gpg would have reported
    keyring = tmp_path / "keyring.gpg"
    keyring.write_bytes(b"keyring")
    state = {"status": status_line(), "commands": []}

    def run_output_command(cmd, **kwargs):
        state["commands"].append(cmd)
        return state["status"]

    monkeypatch.setattr(
        autoinstall.programs, "is_tool_installed", lambda name: name == "Gpg")
    monkeypatch.setattr(autoinstall.programs, "get_tool_program", lambda name: "/tools/gpg")
    monkeypatch.setattr(autoinstall.command, "run_output_command", run_output_command)
    state["keyring"] = str(keyring)
    return state


def check_signature(signature_check, tmp_path, **kwargs):
    listing = tmp_path / "SHA256SUMS"
    listing.write_text("")
    signature = tmp_path / "SHA256SUMS.gpg"
    signature.write_bytes(b"")
    defaults = dict(
        listing_file = str(listing),
        signature_file = str(signature),
        keyring_file = signature_check["keyring"],
        fingerprint = UBUNTU_FINGERPRINT)
    defaults.update(kwargs)
    return autoinstall.verify_checksum_signature(**defaults)


def test_the_signature_is_published_beside_the_checksums():
    assert autoinstall.get_checksum_signature_url("24.04") == \
        "https://releases.ubuntu.com/24.04/SHA256SUMS.gpg"


def test_a_signature_from_the_expected_key_is_accepted(signature_check, tmp_path):
    assert check_signature(signature_check, tmp_path) is True


def test_the_signature_is_checked_against_the_given_keyring(signature_check, tmp_path):
    # Checking against whatever keys happen to be on the machine would accept
    # a signature from any of them.
    check_signature(signature_check, tmp_path)
    command = signature_check["commands"][0]

    assert "--no-default-keyring" in command
    assert signature_check["keyring"] in command


def test_a_signature_that_does_not_check_out_is_refused(signature_check, tmp_path):
    # gpg reports nothing valid when the listing was changed after signing.
    signature_check["status"] = "[GNUPG:] BADSIG 843938DF228D22F7B3742BC0D94AA3F0EFE21092\n"

    assert check_signature(signature_check, tmp_path) is False


def test_a_signature_from_another_key_is_refused(signature_check, tmp_path):
    # The keyring may hold many keys; only one publishes these images.
    signature_check["status"] = status_line("0" * 40)

    assert check_signature(signature_check, tmp_path) is False


def test_a_fingerprint_is_compared_however_it_is_written(signature_check, tmp_path):
    # gpg prints fingerprints in spaced groups.
    spaced = "8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092"

    assert check_signature(signature_check, tmp_path, fingerprint = spaced) is True


def test_any_trusted_key_is_accepted_when_none_is_named(signature_check, tmp_path):
    signature_check["status"] = status_line("0" * 40)

    assert check_signature(signature_check, tmp_path, fingerprint = "") is True


def test_a_missing_keyring_is_reported(signature_check, tmp_path):
    assert check_signature(
        signature_check, tmp_path, keyring_file = str(tmp_path / "absent.gpg")) is False


def test_a_signature_cannot_be_checked_without_gpg(monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(autoinstall.programs, "get_tool_program", lambda name: None)
    listing = tmp_path / "SHA256SUMS"
    listing.write_text("")

    assert autoinstall.verify_checksum_signature(str(listing), str(listing)) is False


@pytest.mark.parametrize("status", ["", None, "gpg: no valid OpenPGP data found"])
def test_an_unreadable_verification_is_refused(signature_check, tmp_path, status):
    signature_check["status"] = status

    assert check_signature(signature_check, tmp_path) is False


def test_the_reported_fingerprint_is_read_from_the_status():
    assert autoinstall.get_verified_fingerprint(status_line()) == UBUNTU_FINGERPRINT


def test_byte_status_output_is_decoded():
    assert autoinstall.get_verified_fingerprint(status_line().encode()) == UBUNTU_FINGERPRINT


def test_the_signing_key_is_configurable(isolated_settings, tmp_path):
    # A release signed by a different key, or a machine that keeps its
    # keyrings somewhere else.
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_signing_fingerprint", "0" * 40)
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_signing_keyring", str(tmp_path / "other.gpg"))

    assert autoinstall.get_signing_fingerprint() == "0" * 40
    assert autoinstall.get_signing_keyring() == str(tmp_path / "other.gpg")


def test_the_ubuntu_signing_key_is_expected_by_default(isolated_settings):
    assert autoinstall.get_signing_fingerprint() == UBUNTU_FINGERPRINT


###########################################################
# Fetching the checksums
###########################################################

@pytest.fixture
def published_files(monkeypatch, tmp_path):
    state = {
        "listing": checksum_listing((CHECKSUM, image_named("24.04.1"))),
        "downloaded": [],
        "signature_ok": True,
    }

    def download_url(url, output_file, **kwargs):
        state["downloaded"].append(url)
        with open(output_file, "w") as handle:
            handle.write(state["listing"] if url.endswith("SHA256SUMS") else "signature")
        return True

    monkeypatch.setattr(autoinstall.network, "download_url", download_url)
    monkeypatch.setattr(
        autoinstall, "verify_checksum_signature", lambda **kwargs: state["signature_ok"])
    return state


def test_the_checksums_and_their_signature_are_both_fetched(published_files, tmp_path):
    checksums = autoinstall.fetch_release_checksums("24.04", str(tmp_path))

    assert checksums[image_named("24.04.1")] == CHECKSUM
    assert any(url.endswith("SHA256SUMS") for url in published_files["downloaded"])
    assert any(url.endswith("SHA256SUMS.gpg") for url in published_files["downloaded"])


def test_checksums_that_are_not_correctly_signed_are_not_used(published_files, tmp_path):
    published_files["signature_ok"] = False

    assert autoinstall.fetch_release_checksums("24.04", str(tmp_path)) is None


def test_the_signature_check_can_be_turned_off(published_files, tmp_path):
    checksums = autoinstall.fetch_release_checksums(
        "24.04", str(tmp_path), verify_signature = False)

    assert checksums[image_named("24.04.1")] == CHECKSUM
    assert not any(url.endswith(".gpg") for url in published_files["downloaded"])


def test_checksums_that_cannot_be_fetched_are_nothing(published_files, monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall.network, "download_url", lambda **kwargs: False)

    assert autoinstall.fetch_release_checksums("24.04", str(tmp_path)) is None
