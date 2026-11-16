# Ubuntu Server releases: finding the newest image of a release and checking it
# against the published checksums, whose signature is verified first.

# Imports
import re

# Local imports
from joybox import command
from joybox import fileops
from joybox import hashing
from joybox import logger
from joybox import network
from joybox import paths
from joybox import programs
from joybox import serialization
from joybox import settings

# Where the releases are published
releases_url_base = "https://releases.ubuntu.com"

# The key the checksum listings are signed with, and where a distribution
# keeps a copy of it. Both are settings, since a release may be signed by a
# different key and a machine may keep its keyrings elsewhere.
default_signing_fingerprint = "843938DF228D22F7B3742BC0D94AA3F0EFE21092"
default_keyring_file = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"

###########################################################
# Releases
###########################################################

# Get release listing url
def get_release_listing_url(version):
    return "%s/%s/" % (releases_url_base, version)

# Find the server images published for a release
def find_release_images(version, verbose = False, pretend_run = False, exit_on_failure = False):
    listing = network.get_remote_html(
        url = get_release_listing_url(version),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not listing:
        return []
    found = set(re.findall(r"ubuntu-[0-9.]+-live-server-amd64\.iso", listing))
    return sorted(found, key = get_image_version)

# Get the version an image filename carries, as numbers
# Sorting these as text puts 24.04.10 before 24.04.2, which picks an older
# point release as the newest one.
def get_image_version(image):
    found = re.search(r"ubuntu-([0-9.]+)-live-server", image)
    if not found:
        return ()
    parts = []
    for token in found.group(1).split("."):
        if token.isdigit():
            parts.append(int(token))
    return tuple(parts)

# Find the newest server image published for a release
def find_latest_release_image(version, verbose = False, pretend_run = False, exit_on_failure = False):
    images = find_release_images(
        version = version,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not images:
        logger.log_error("No Ubuntu %s server images found at %s" % (
            version, get_release_listing_url(version)))
        return None
    return images[-1]

# Find the download url of the newest server image for a release
def find_latest_release_url(version, verbose = False, pretend_run = False, exit_on_failure = False):
    image = find_latest_release_image(
        version = version,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not image:
        return None
    return get_release_listing_url(version) + image

# Get the volume name for a release
def get_volume_name(version):
    return "Ubuntu-Server %s" % version

###########################################################
# Verification
#
# The image is downloaded over the network and then booted on a machine that
# installs itself from it. A truncated download or a substituted image is
# only noticed once it is already running, so the published checksum is
# checked before anything is built from it.
###########################################################

# Get the checksum listing url for a release
def get_checksum_listing_url(version):
    return "%s%s" % (get_release_listing_url(version), "SHA256SUMS")

# Get the url of the signature over the checksum listing
def get_checksum_signature_url(version):
    return "%s%s" % (get_release_listing_url(version), "SHA256SUMS.gpg")

# Get the keyring the checksums' signature is checked against; without it the
# checksums are only as trustworthy as the connection that fetched them
def get_signing_keyring():
    return settings.get_path_value(
        "UserData.Autoinstall", "autoinstall_signing_keyring",
        default_keyring_file, throw_exception = False)

# Get the key the listing is expected to be signed by
def get_signing_fingerprint():
    return settings.get_value(
        "UserData.Autoinstall", "autoinstall_signing_fingerprint",
        default_signing_fingerprint, throw_exception = False)

# Get the signature verification tool
def get_signature_tool():
    if programs.is_tool_installed("Gpg"):
        return programs.get_tool_program("Gpg")
    logger.log_error("Gpg was not found")
    return None

# Read the fingerprint a verification reported
# A signature that checks out against a keyring only says it was made by one
# of the keys in it, so the key itself is checked as well.
def get_verified_fingerprint(status_output):
    if not status_output:
        return None
    if isinstance(status_output, bytes):
        status_output = status_output.decode(errors = "replace")
    for line in status_output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG":
            return parts[2].upper()
    return None

# Check the signature over a checksum listing
def verify_checksum_signature(
    listing_file,
    signature_file,
    keyring_file = None,
    fingerprint = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    signature_tool = get_signature_tool()
    if not signature_tool:
        return False

    # Get the key to check against
    if keyring_file is None:
        keyring_file = get_signing_keyring()
    if fingerprint is None:
        fingerprint = get_signing_fingerprint()
    if not paths.is_path_file(keyring_file):
        logger.log_error("Signing keyring not found: %s" % keyring_file)
        return False

    # Get verify command
    verify_cmd = [
        signature_tool,
        "--no-default-keyring",
        "--keyring", keyring_file,
        "--status-fd", "1",
        "--verify", signature_file, listing_file,
    ]

    # Run verify command
    status_output = command.run_output_command(
        cmd = verify_cmd,
        verbose = verbose,
        pretend_run = False,
        exit_on_failure = exit_on_failure)
    verified = get_verified_fingerprint(status_output)
    if not verified:
        logger.log_error("The checksums for this release are not correctly signed")
        return False

    # Check it was the expected key
    if fingerprint and verified != fingerprint.replace(" ", "").upper():
        logger.log_error("The checksums were signed by an unexpected key")
        logger.log_error("  expected: %s" % fingerprint)
        logger.log_error("  signed by: %s" % verified)
        return False
    return True

# Fetch the published checksums for a release
def fetch_release_checksums(
    version,
    work_dir,
    verify_signature = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get the listing itself
    listing_file = paths.join_paths(work_dir, "SHA256SUMS")
    success = network.download_url(
        url = get_checksum_listing_url(version),
        output_file = listing_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download the checksums for Ubuntu %s" % version)
        return None

    # Check who signed it
    if verify_signature:
        signature_file = paths.join_paths(work_dir, "SHA256SUMS.gpg")
        success = network.download_url(
            url = get_checksum_signature_url(version),
            output_file = signature_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to download the signature for Ubuntu %s" % version)
            return None
        success = verify_checksum_signature(
            listing_file = listing_file,
            signature_file = signature_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

    # Read it
    return parse_checksum_listing(serialization.read_text_file(
        src = listing_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure))

# Read the published checksums for a release
def find_release_checksums(version, verbose = False, pretend_run = False, exit_on_failure = False):
    listing = network.get_remote_html(
        url = get_checksum_listing_url(version),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return parse_checksum_listing(listing)

# Parse a published checksum listing
# Each line is a checksum, then a marker, then the filename it belongs to.
def parse_checksum_listing(listing):
    checksums = {}
    if not listing:
        return checksums
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        checksum, filename = parts
        if len(checksum) != 64:
            continue
        checksums[filename.lstrip("*")] = checksum.lower()
    return checksums

# Find the published checksum for one image
def find_image_checksum(version, image, verbose = False, pretend_run = False, exit_on_failure = False):
    checksums = find_release_checksums(
        version = version,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return checksums.get(image)

# Check a downloaded image against its published checksum
def verify_image_checksum(
    iso_file,
    version,
    image,
    verify_signature = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # A pretend run downloads nothing, so there is nothing to check
    if pretend_run:
        logger.log_info("Would verify %s against the published checksum for %s" % (iso_file, image))
        return True

    # Read the published checksums, having checked who signed them
    work_dir_ok, work_dir = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not work_dir_ok:
        logger.log_error("Unable to create temporary directory")
        return False
    try:
        checksums = fetch_release_checksums(
            version = version,
            work_dir = work_dir,
            verify_signature = verify_signature,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    finally:
        fileops.remove_directory(
            src = work_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
    expected = (checksums or {}).get(image)
    if not expected:
        logger.log_error("No published checksum was found for %s" % image)
        return False
    logger.log_info("Verifying %s" % iso_file)
    actual = hashing.calculate_file_sha256(
        src = iso_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not actual or actual.lower() != expected:
        logger.log_error("Checksum mismatch for %s" % iso_file)
        logger.log_error("  published: %s" % expected)
        logger.log_error("  actual:    %s" % (actual or "unreadable"))
        return False
    return True
