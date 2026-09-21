# Imports
import copy
import os, os.path
import re

# Local imports
import joybox.config as config
import joybox.command as command
import joybox.fileops as fileops
import joybox.hashing as hashing
import joybox.logger as logger
import joybox.network as network
import joybox.paths as paths
import joybox.programs as programs
import joybox.serialization as serialization
import joybox.settings as settings

###########################################################
# Ubuntu autoinstall images
#
# Builds an Ubuntu Server image that installs itself: the stock ISO with a
# cloud-init NoCloud seed added and its bootloader pointed at that seed. The
# machine being installed has no keyboard attached to it, so anything the
# installer would otherwise ask for has to be answered in advance.
###########################################################

# Where the releases are published
releases_url_base = "https://releases.ubuntu.com"

# The seed directory added to the image, and where it appears once booted
seed_directory = "nocloud"
seed_source = "/cdrom/%s/" % seed_directory

# The stock ISO waits for a menu choice; this is how long it waits before
# installing itself, in seconds
boot_timeout = 2

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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    expected = find_image_checksum(
        version = version,
        image = image,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not expected:
        logger.log_error("No published checksum was found for %s" % image)
        return False
    if pretend_run:
        return True
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

###########################################################
# Install profile
###########################################################

# Get install profile
# Everything the installer would have asked a person sitting at the machine.
def get_install_profile():
    return {
        "version": settings.get_value(
            "UserData.Autoinstall", "autoinstall_version", "24.04", throw_exception = False),
        "username": settings.get_value(
            "UserData.Autoinstall", "autoinstall_username", "", throw_exception = False),
        "realname": settings.get_value(
            "UserData.Autoinstall", "autoinstall_realname", "", throw_exception = False),
        "hostname": settings.get_value(
            "UserData.Autoinstall", "autoinstall_hostname", "ubuntu", throw_exception = False),
        "password_hash": settings.get_value(
            "UserData.Autoinstall", "autoinstall_password_hash", "", throw_exception = False),
        "ssh_keys": settings.get_list_value(
            "UserData.Autoinstall", "autoinstall_ssh_keys", default_value = [], throw_exception = False),
        "locale": settings.get_value(
            "UserData.Autoinstall", "autoinstall_locale", "en_US.UTF-8", throw_exception = False),
        "keyboard": settings.get_value(
            "UserData.Autoinstall", "autoinstall_keyboard", "us", throw_exception = False),
        "timezone": settings.get_value(
            "UserData.Autoinstall", "autoinstall_timezone", "Etc/UTC", throw_exception = False),
        "packages": settings.get_list_value(
            "UserData.Autoinstall", "autoinstall_packages", default_value = [], throw_exception = False),
        "serial_console": settings.get_bool_value(
            "UserData.Autoinstall", "autoinstall_serial_console", False, throw_exception = False),
        "overlay_file": settings.get_path_value(
            "UserData.Autoinstall", "autoinstall_overlay_file", "", throw_exception = False),
    }

# Check if install profile is complete
# An incomplete profile produces an installer that stops and waits for the
# answer it is missing, which is the one thing the image exists to avoid.
def is_install_profile_complete(profile):
    if not isinstance(profile, dict):
        return False
    if not profile.get("username"):
        return False
    if not profile.get("hostname"):
        return False
    if not profile.get("password_hash") and not profile.get("ssh_keys"):
        return False
    return True

# Describe what an install profile is missing
def get_install_profile_problems(profile):
    problems = []
    if not isinstance(profile, dict):
        return ["No profile was given"]
    if not profile.get("username"):
        problems.append("No username is set (autoinstall_username)")
    if not profile.get("hostname"):
        problems.append("No hostname is set (autoinstall_hostname)")
    if not profile.get("password_hash") and not profile.get("ssh_keys"):
        problems.append(
            "No password hash or ssh key is set "
            "(autoinstall_password_hash or autoinstall_ssh_keys); "
            "the installed machine would have no way to log in")
    return problems

###########################################################
# Cloud-init seed
###########################################################

# Build the storage layout
# One disk, gpt, an efi partition and the rest as root. The machine is being
# installed from scratch, so the existing contents are replaced.
def build_storage_config():
    return {
        "config": [
            {
                "type": "disk",
                "id": "disk0",
                "match": {"size": "largest"},
                "ptable": "gpt",
                "wipe": "superblock-recursive",
                "preserve": False,
                "grub_device": True,
            },
            {
                "type": "partition",
                "id": "part_efi",
                "device": "disk0",
                "size": "512M",
                "flag": "boot",
                "grub_device": True,
                "preserve": False,
            },
            {"type": "format", "id": "fmt_efi", "fstype": "fat32", "volume": "part_efi", "preserve": False},
            {"type": "partition", "id": "part_root", "device": "disk0", "size": -1, "preserve": False},
            {"type": "format", "id": "fmt_root", "fstype": "ext4", "volume": "part_root", "preserve": False},
            {"type": "mount", "id": "mount_root", "device": "fmt_root", "path": "/"},
            {"type": "mount", "id": "mount_efi", "device": "fmt_efi", "path": "/boot/efi"},
        ]
    }

# Build the accounts the installed machine will have
def build_user_config(profile):
    account = {
        "name": profile.get("username"),
        "gecos": profile.get("realname") or profile.get("username"),
        "sudo": "ALL=(ALL) NOPASSWD:ALL",
        "groups": ["sudo"],
        "shell": "/bin/bash",
    }
    ssh_keys = [key for key in profile.get("ssh_keys", []) if key]
    if ssh_keys:
        account["ssh_authorized_keys"] = ssh_keys
    return {
        "users": ["default", account],
        "write_files": [
            {
                "path": "/etc/ssh/sshd_config.d/99-disable-password.conf",
                "content": "PasswordAuthentication no\n",
                "permissions": "0644",
            },
        ],
    }

# Build the autoinstall document
def build_autoinstall_config(profile):
    autoinstall = {
        "version": 1,
        "locale": profile.get("locale"),
        "keyboard": {"layout": profile.get("keyboard")},
        "timezone": profile.get("timezone"),
        "ssh": {"install-server": True, "allow-pw": False},
        "storage": build_storage_config(),
        "identity": {
            "realname": profile.get("realname") or profile.get("username"),
            "username": profile.get("username"),
            "hostname": profile.get("hostname"),
            "password": profile.get("password_hash"),
        },
        "user-data": build_user_config(profile),
        "late-commands": [
            "curtin in-target --target=/target -- systemctl enable ssh",
        ],
    }
    packages = [package for package in profile.get("packages", []) if package]
    if packages:
        autoinstall["packages"] = packages
        for package in packages:
            autoinstall["late-commands"].append(
                "curtin in-target --target=/target -- systemctl enable %s || true" % package)
    return {"autoinstall": autoinstall}

# Build the user-data seed file contents
def build_user_data(profile, overlay = None):
    import yaml

    body = yaml.safe_dump(
        merge_autoinstall_data(build_autoinstall_config(profile), overlay),
        sort_keys = False,
        default_flow_style = False)
    return "#cloud-config\n%s" % body

# Build the meta-data seed file contents
def build_meta_data(profile):
    return "instance-id: autoinstall\nlocal-hostname: %s\n" % profile.get("hostname", "ubuntu")

###########################################################
# Overlays
#
# The generated document covers what the installer must have: a disk layout,
# an account and a way in. Everything else a machine needs - extra packages,
# snaps, files, commands that fetch something and run it - is whatever the
# person building the image wants, so it comes from a file they keep.
###########################################################

# Keys whose lists are added to rather than replaced
# Replacing them would silently drop the account and the disk layout the
# generated document established.
merge_list_keys = [
    "packages",
    "snaps",
    "late-commands",
    "early-commands",
    "users",
    "write_files",
    "runcmd",
]

# Merge an overlay into a generated document
def merge_autoinstall_data(base, overlay):
    if not isinstance(overlay, dict):
        return base
    if not isinstance(base, dict):
        return copy.deepcopy(overlay)
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = merge_autoinstall_data(existing, value)
        elif isinstance(existing, list) and isinstance(value, list) and key in merge_list_keys:
            merged[key] = existing + [entry for entry in value if entry not in existing]
        else:
            merged[key] = copy.deepcopy(value)
    return merged

# Read an overlay file
# The file may be written as a whole autoinstall document or as just the
# contents of one, so both are accepted.
def read_overlay_file(overlay_file, verbose = False, pretend_run = False, exit_on_failure = False):
    if not paths.is_path_file(overlay_file):
        logger.log_error("Overlay file not found: %s" % overlay_file)
        return None
    data = serialization.read_yaml_file(
        src = overlay_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not isinstance(data, dict) or not data:
        logger.log_error("Overlay file is empty or unreadable: %s" % overlay_file)
        return None
    if "autoinstall" in data:
        return data
    return {"autoinstall": data}

# Write the seed into an extracted image
# It goes in its own directory rather than the image root, so it cannot be
# confused with the files the stock image already ships.
def write_seed_files(
    iso_dir,
    profile,
    overlay = None,
    user_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    seed_dir = paths.join_paths(iso_dir, seed_directory)
    success = fileops.make_directory(
        src = seed_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    for filename, contents in [
        ("user-data", user_data if user_data else build_user_data(profile, overlay)),
        ("meta-data", build_meta_data(profile)),
    ]:
        success = serialization.write_text_file(
            src = paths.join_paths(seed_dir, filename),
            contents = contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

###########################################################
# Boot configuration
###########################################################

# Get the kernel arguments that point the installer at the seed
def get_kernel_arguments(profile = None):
    arguments = ["autoinstall", "ds=nocloud;s=%s" % seed_source]
    if profile and profile.get("serial_console"):
        arguments.append("console=ttyS0")
    return arguments

# Add the kernel arguments to one boot entry line
def patch_boot_entry(line, profile = None):
    arguments = get_kernel_arguments(profile)

    # Already pointed at the seed
    if arguments[0] in line:
        return line

    # The stock entries end their kernel arguments at a --- separator, and
    # anything added after it goes to the installed system rather than the
    # installer, which quietly means no autoinstall at all. The separator is
    # written both as "--- " and as "---" at the end of the line.
    addition = " " + " ".join(arguments)
    separator = re.search(r"\s---(\s|$)", line)
    if separator:
        return line[:separator.start()] + addition + line[separator.start():]
    return line.rstrip("\n") + addition + ("\n" if line.endswith("\n") else "")

# Patch the contents of a boot configuration
def patch_boot_config_contents(contents, profile = None):
    patched = []
    for line in contents.splitlines(keepends = True):
        stripped = line.strip()
        if stripped.startswith("linux") or stripped.startswith("append"):
            patched.append(patch_boot_entry(line, profile))
        elif stripped.startswith("set timeout="):
            leading = line[:len(line) - len(line.lstrip())]
            patched.append("%sset timeout=%d\n" % (leading, boot_timeout))
        elif stripped.startswith("timeout "):
            leading = line[:len(line) - len(line.lstrip())]
            patched.append("%stimeout %d\n" % (leading, boot_timeout * 10))
        else:
            patched.append(line)
    return "".join(patched)

# Get the boot configurations an extracted image may carry
def get_boot_config_files(iso_dir):
    return [
        paths.join_paths(iso_dir, "boot", "grub", "grub.cfg"),
        paths.join_paths(iso_dir, "boot", "grub", "loopback.cfg"),
        paths.join_paths(iso_dir, "isolinux", "txt.cfg"),
    ]

# Patch every boot configuration present in an extracted image
def patch_boot_configs(
    iso_dir,
    profile = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    patched_any = False
    for config_file in get_boot_config_files(iso_dir):
        if not paths.is_path_file(config_file):
            continue
        contents = serialization.read_text_file(
            src = config_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not contents:
            continue
        success = serialization.write_text_file(
            src = config_file,
            contents = patch_boot_config_contents(contents, profile),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        patched_any = True
    if not patched_any and not pretend_run:
        logger.log_error("No boot configuration was found in %s" % iso_dir)
        return False
    return True

###########################################################
# Image handling
###########################################################

# Get the image tool
def get_image_tool():
    if programs.is_tool_installed("XorrISO"):
        return programs.get_tool_program("XorrISO")
    logger.log_error("XorrISO was not found")
    return None

# Extract an image so its contents can be changed
def extract_image(
    iso_file,
    iso_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    image_tool = get_image_tool()
    if not image_tool:
        return False
    success = fileops.make_directory(
        src = iso_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    extract_cmd = [
        image_tool,
        "-osirrox", "on",
        "-indev", iso_file,
        "-extract", "/", iso_dir,
    ]
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [iso_dir],
            blocking_processes = [image_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to extract %s" % iso_file)
        return False

    # The extracted tree comes out read only, and the seed has to be added
    fileops.chmod_file_or_directory(
        src = iso_dir,
        perms = 644,
        dperms = 755,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Extract the boot images an extracted tree does not carry as ordinary files
# The efi image lives in the El Torito catalogue rather than the filesystem,
# and rebuilding without it produces an image no UEFI machine will boot.
def extract_boot_images(
    iso_file,
    iso_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    image_tool = get_image_tool()
    if not image_tool:
        return False
    if paths.is_path_file(get_efi_image_file(iso_dir)):
        return True
    extract_cmd = [
        image_tool,
        "-osirrox", "on",
        "-indev", iso_file,
        "-extract_boot_images", iso_dir,
    ]
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [iso_dir],
            blocking_processes = [image_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to extract boot images from %s" % iso_file)
        return False
    return rename_extracted_boot_image(
        iso_dir = iso_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Get the efi image an extracted tree should carry
def get_efi_image_file(iso_dir):
    return paths.join_paths(iso_dir, "efi.img")

# Put the extracted boot image where the rebuild expects it
def rename_extracted_boot_image(
    iso_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if pretend_run:
        return True
    for candidate in sorted(paths.get_directory_contents(iso_dir)):
        if candidate.startswith("eltorito_img") and candidate.endswith(".img"):
            return fileops.move_file_or_directory(
                src = paths.join_paths(iso_dir, candidate),
                dest = get_efi_image_file(iso_dir),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    logger.log_error("No efi boot image was found in %s" % iso_dir)
    return False

# Build the command that repacks an extracted tree as a bootable image
# The image has to boot both ways: the bios entry from the El Torito image
# and the uefi entry from the efi image, with the hybrid layout that lets the
# same file be written to a usb stick.
def get_repack_command(image_tool, iso_file, iso_dir, volume_name):
    return [
        image_tool,
        "-as", "mkisofs",
        "-r",
        "-V", volume_name,
        "-J", "-l",
        "-b", "boot/grub/i386-pc/eltorito.img",
        "-c", "boot.catalog",
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        "-eltorito-alt-boot",
        "-e", "efi.img",
        "-no-emul-boot",
        "-isohybrid-gpt-basdat",
        "-o", iso_file,
        iso_dir,
    ]

# Get the volume name for a release
def get_volume_name(version):
    return "Ubuntu-Server %s" % version

# Repack an extracted tree as a bootable image
def repack_image(
    iso_file,
    iso_dir,
    volume_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    image_tool = get_image_tool()
    if not image_tool:
        return False
    code = command.run_returncode_command(
        cmd = get_repack_command(image_tool, iso_file, iso_dir, volume_name),
        options = command.create_command_options(
            output_paths = [iso_file],
            blocking_processes = [image_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to package %s" % iso_file)
        return False
    if pretend_run:
        return True
    return paths.is_path_file(iso_file)

###########################################################
# Building
###########################################################

# Get a stock image, downloading it only when it is not already here
def obtain_source_image(
    output_file,
    version,
    source_file = None,
    verify = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Already have one. A caller supplied image is taken as given, since it
    # need not be a published release at all; one left by an earlier run is
    # checked, because a truncated download looks exactly like a good one.
    if paths.is_path_file(source_file):
        return source_file
    if paths.is_path_file(output_file):
        logger.log_info("Using the image already downloaded: %s" % output_file)
        if not verify:
            return output_file
        image = find_latest_release_image(
            version = version,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if image and verify_image_checksum(
            iso_file = output_file,
            version = version,
            image = image,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            return output_file
        logger.log_warning("Discarding %s and downloading it again" % output_file)
        fileops.remove_file(
            src = output_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

    # Fetch the newest one published
    image = find_latest_release_image(
        version = version,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not image:
        return None
    release_url = get_release_listing_url(version) + image
    logger.log_info("Downloading %s" % release_url)
    success = network.download_url(
        url = release_url,
        output_file = output_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download %s" % release_url)
        return None

    # Check it against what was published before building from it
    if verify:
        verified = verify_image_checksum(
            iso_file = output_file,
            version = version,
            image = image,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not verified:

            # A bad download left in place is picked up as "already here" by
            # the next run, which would never recover on its own
            fileops.remove_file(
                src = output_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            return None
    return output_file

# Build an autoinstall image
def build_autoinstall_image(
    output_file,
    source_file = None,
    download_file = None,
    profile = None,
    overlay_file = None,
    user_data_file = None,
    verify = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check everything the build needs before anything is downloaded
    if profile is None:
        profile = get_install_profile()

    # A whole seed supplied by the caller replaces the generated one, so the
    # profile only has to answer for the parts still being generated
    user_data = None
    if user_data_file:
        if not paths.is_path_file(user_data_file):
            logger.log_error("User data file not found: %s" % user_data_file)
            return False
        user_data = serialization.read_text_file(
            src = user_data_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not user_data:
            logger.log_error("User data file is empty: %s" % user_data_file)
            return False
    else:
        problems = get_install_profile_problems(profile)
        if problems:
            for problem in problems:
                logger.log_error(problem)
            return False

    # Anything the machine needs beyond a working install
    overlay = None
    if not overlay_file:
        overlay_file = profile.get("overlay_file")
    if overlay_file:
        overlay = read_overlay_file(
            overlay_file = overlay_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if overlay is None:
            return False

    # Get the stock image
    version = profile.get("version")
    if not download_file:
        download_file = paths.join_paths(
            paths.get_filename_directory(output_file), "ubuntu-server-%s.iso" % version)
    stock_image = obtain_source_image(
        output_file = download_file,
        version = version,
        source_file = source_file,
        verify = verify,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not stock_image:
        return False

    # Work somewhere disposable
    work_dir_ok, work_dir = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not work_dir_ok:
        logger.log_error("Unable to create temporary directory")
        return False
    iso_dir = paths.join_paths(work_dir, "iso")

    try:

        # Take the image apart
        success = extract_image(
            iso_file = stock_image,
            iso_dir = iso_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = extract_boot_images(
            iso_file = stock_image,
            iso_dir = iso_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Add the answers and point the bootloader at them
        success = write_seed_files(
            iso_dir = iso_dir,
            profile = profile,
            overlay = overlay,
            user_data = user_data,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = patch_boot_configs(
            iso_dir = iso_dir,
            profile = profile,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Put it back together
        success = repack_image(
            iso_file = output_file,
            iso_dir = iso_dir,
            volume_name = get_volume_name(version),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    finally:
        fileops.remove_directory(
            src = work_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

    logger.log_info("Built autoinstall image: %s" % output_file)
    return True
