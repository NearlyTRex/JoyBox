# Imports
import importlib
import copy
import re

# Local imports
from joybox import fileops
from joybox import iso
from joybox import logger
from joybox import network
from joybox import paths
from joybox import serialization
from joybox import settings
from joybox import ubunturelease

# Get yaml, imported on first use
def _get_yaml():
    return importlib.import_module("yaml")

###########################################################
# Ubuntu autoinstall images
#
# Builds an Ubuntu Server image that installs itself: the stock ISO with a
# cloud-init NoCloud seed added and its bootloader pointed at that seed. The
# machine being installed has no keyboard attached to it, so anything the
# installer would otherwise ask for has to be answered in advance.
###########################################################

# The seed directory added to the image, and where it appears once booted
SEED_DIRECTORY = "nocloud"
SEED_SOURCE = "/cdrom/%s/" % SEED_DIRECTORY

# The stock ISO waits for a menu choice; this is how long it waits before
# installing itself, in seconds
BOOT_TIMEOUT = 2

# What goes in the password field when a key is the only way in. An empty
# field is not "no login", it is a login that takes no password, so the
# account is locked instead and the key is left as the way in.
LOCKED_PASSWORD = "!"

# Where the stock image keeps the images it boots from
BIOS_BOOT_IMAGE = "boot/grub/i386-pc/eltorito.img"
# The efi image and the boot code are pulled out of the stock image and kept
# beside the tree rather than inside it, since they are appended to the
# rebuilt image as a partition and a system area rather than packed as files.

###########################################################
# Install profile
###########################################################

# Read a comma separated setting as a list
# Written by hand in an ini file, so a space after a comma is expected, and
# carrying it through would hand apt a package named " git".
def get_profile_list(field):
    values = settings.get_list_value(
        "UserData.Autoinstall", field, default_value = [], throw_exception = False)
    if not values:
        return []
    return [value.strip() for value in values if value and value.strip()]

# Usernames the installer refuses. Taken from the reserved-usernames list
# that ships inside the installer image, at usr/lib/user-setup/reserved-usernames
# in its squashfs. The installer only refuses one once it is already running
# on the target machine, where nobody is watching, so it is checked here.
reserved_usernames = {
    "Debian-exim", "adm", "admin", "alias", "asterisk", "audio", "backup", "bin", "bind",
    "cdrom", "ceph", "crontab", "cupsys", "daemon", "dcc", "dhcp", "dialout", "dictd", "dip",
    "disk", "dnsmasq", "dovecot", "fax", "fetchmail", "firebird", "floppy", "ftn", "ftp",
    "fuse", "games", "gdm", "gnats", "grsec-proc", "grsec-sock-all", "grsec-sock-clt",
    "grsec-sock-srv", "grsec-tpe", "haclient", "hacluster", "haldaemon", "hplilp", "identd",
    "input", "irc", "jwhois", "klog", "kmem", "kvm", "libvirt-qemu", "list", "lp", "lpadmin",
    "maas", "mail", "man", "messagebus", "mysql", "mythtv", "netdev", "netplan", "news",
    "nobody", "nogroup", "opensrf", "operator", "plugdev", "powerdev", "proxy", "qmail",
    "qmaild", "qmaill", "qmailp", "qmailq", "qmailr", "qmails", "radvd", "render", "root",
    "saned", "sasl", "sbuild", "scanner", "sgx", "shadow", "slocate", "slurm", "src", "ssh",
    "sshd", "ssl-cert", "sslwrap", "staff", "statd", "sudo", "sync", "sys", "syslog",
    "tac-plus", "tape", "telnetd", "tftpd", "tty", "users", "utmp", "uucp", "vchkpw", "video",
    "voice", "vpopmail", "www-data"
}

# What the installer accepts as a username
USERNAME_PATTERN = r"^[a-z_][a-z0-9_-]*[$]?$"

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
        "ssh_keys": get_profile_list("autoinstall_ssh_keys"),
        "locale": settings.get_value(
            "UserData.Autoinstall", "autoinstall_locale", "en_US.UTF-8", throw_exception = False),
        "keyboard": settings.get_value(
            "UserData.Autoinstall", "autoinstall_keyboard", "us", throw_exception = False),
        "timezone": settings.get_value(
            "UserData.Autoinstall", "autoinstall_timezone", "Etc/UTC", throw_exception = False),
        "packages": get_profile_list("autoinstall_packages"),
        "serial_console": settings.get_bool_value(
            "UserData.Autoinstall", "autoinstall_serial_console", False, throw_exception = False),
        "overlay_file": settings.get_path_value(
            "UserData.Autoinstall", "autoinstall_overlay_file", "", throw_exception = False),
    }

# Check if install profile is complete
# An incomplete profile produces an installer that stops and waits for the
# answer it is missing, which is the one thing the image exists to avoid.
def is_install_profile_complete(profile):
    return not get_install_profile_problems(profile)

# Describe what an install profile is missing
def get_install_profile_problems(profile):
    problems = []
    if not isinstance(profile, dict):
        return ["No profile was given"]
    username = profile.get("username")
    if not username:
        problems.append("No username is set (autoinstall_username)")
    elif username in reserved_usernames:
        problems.append(
            "Username %s is reserved by the system and the installer will "
            "refuse it (autoinstall_username)" % username)
    elif not re.match(USERNAME_PATTERN, username):
        problems.append(
            "Username %s is not one the installer accepts; use lower case "
            "letters, digits, dashes and underscores (autoinstall_username)"
            % username)
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

# Build the storage layout: the whole largest disk, ext4 root, no LVM. The
# installer's own layout picks the boot partition, efi under UEFI or bios_grub
# under BIOS, since only the target knows; a fixed list breaks grub on the other
def build_storage_config():
    return {
        "layout": {
            "name": "direct",
            "match": {"size": "largest"},
        }
    }

# Build the network configuration, matching ports by en*/eth* rather than the
# pci-slot names the installer saw, which change when a card moves; optional, so
# a port with no cable does not hold up the boot
def build_network_config():
    return {
        "version": 2,
        "ethernets": {
            "wired-en": {"match": {"name": "en*"}, "dhcp4": True, "optional": True},
            "wired-eth": {"match": {"name": "eth*"}, "dhcp4": True, "optional": True},
        },
    }

# Where the sshd settings are written. sshd keeps the first value it reads
# for a setting, and this sorts before the 50-cloud-init.conf cloud-init
# writes, so these win.
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config.d/10-joybox.conf"

# Build the sshd settings every installed machine gets: key-only login for the
# account made here, and local port forwarding, so a service bound to localhost
# is reachable through a tunnel, but no other forwarding
def build_sshd_config(username):
    return (
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PermitRootLogin no\n"
        "AllowUsers %s\n"
        "MaxAuthTries 3\n"
        "X11Forwarding no\n"
        "AllowAgentForwarding no\n"
        "AllowTcpForwarding local\n" % username)

# Build the accounts the installed machine will have
# Only the one account: cloud-init's "default" entry would add the distro's
# own user (ubuntu) with passwordless sudo beside it.
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
        "users": [account],
        "write_files": [
            {
                "path": SSHD_CONFIG_PATH,
                "content": build_sshd_config(profile.get("username")),
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
        "network": build_network_config(),
        "storage": build_storage_config(),
        "identity": {
            "realname": profile.get("realname") or profile.get("username"),
            "username": profile.get("username"),
            "hostname": profile.get("hostname"),
            "password": profile.get("password_hash") or LOCKED_PASSWORD,
        },
        "user-data": build_user_config(profile),
        "late-commands": [
            "curtin in-target --target=/target -- systemctl enable ssh",
        ],

        # The target may have no display at all, and a reboot with the stick
        # still ahead of the disk in the boot order installs over again. A
        # machine that turns itself off is finished and safe to unplug.
        "shutdown": "poweroff",
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
    yaml = _get_yaml()

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
def read_overlay_file(overlay_file, verbose = False, exit_on_failure = False):
    if not paths.is_path_file(overlay_file):
        logger.log_error("Overlay file not found: %s" % overlay_file)
        return None
    data = serialization.read_yaml_file(
        src = overlay_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not isinstance(data, dict) or not data:
        logger.log_error("Overlay file is empty or unreadable: %s" % overlay_file)
        return None
    if "autoinstall" in data:
        if not isinstance(data["autoinstall"], dict) or not data["autoinstall"]:
            logger.log_error("Overlay file is empty or unreadable: %s" % overlay_file)
            return None
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
    seed_dir = paths.join_paths(iso_dir, SEED_DIRECTORY)
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

# Get the kernel arguments that point the installer at the seed. Grub reads the
# seed's semicolon as a command break and boots an interactive installer, so it
# is escaped for grub; isolinux takes it as written
def get_kernel_arguments(profile = None, escape_semicolons = False):
    seed_argument = "ds=nocloud;s=%s" % SEED_SOURCE
    if escape_semicolons:
        seed_argument = seed_argument.replace(";", "\\;")
    arguments = ["autoinstall", seed_argument]
    if profile and profile.get("serial_console"):
        arguments.append("console=ttyS0")
    return arguments

# Add the kernel arguments to one boot entry line
def patch_boot_entry(line, profile = None, escape_semicolons = False):
    arguments = get_kernel_arguments(profile, escape_semicolons)

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
def patch_boot_config_contents(contents, profile = None, escape_semicolons = False):
    patched = []
    for line in contents.splitlines(keepends = True):
        stripped = line.strip()
        if stripped.startswith("linux") or stripped.startswith("append"):
            patched.append(patch_boot_entry(line, profile, escape_semicolons))
        elif stripped.startswith("set timeout="):
            leading = line[:len(line) - len(line.lstrip())]
            patched.append("%sset timeout=%d\n" % (leading, BOOT_TIMEOUT))
        elif stripped.startswith("timeout "):
            leading = line[:len(line) - len(line.lstrip())]
            patched.append("%stimeout %d\n" % (leading, BOOT_TIMEOUT * 10))
        else:
            patched.append(line)
    return "".join(patched)

# Get the boot configurations an extracted image may carry, and whether each
# one is read by grub, which needs the seed argument escaped
def get_boot_config_files(iso_dir):
    return [
        (paths.join_paths(iso_dir, "boot", "grub", "grub.cfg"), True),
        (paths.join_paths(iso_dir, "boot", "grub", "loopback.cfg"), True),
        (paths.join_paths(iso_dir, "isolinux", "txt.cfg"), False),
    ]

# Patch every boot configuration present in an extracted image
def patch_boot_configs(
    iso_dir,
    profile = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    patched_any = False
    for config_file, escape_semicolons in get_boot_config_files(iso_dir):
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
            contents = patch_boot_config_contents(contents, profile, escape_semicolons),
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
# Building
###########################################################

# Get a stock image, downloading it only when it is not already here
def obtain_source_image(
    output_file,
    version,
    source_file = None,
    verify = True,
    verify_signature = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Already have one. A caller supplied image is taken as given, since it
    # need not be a published release at all; one left by an earlier run is
    # checked, because a truncated download looks exactly like a good one.
    if source_file:
        if paths.is_path_file(source_file):
            return source_file
        logger.log_error("Source image not found: %s" % source_file)
        return None
    if paths.is_path_file(output_file):
        logger.log_info("Using the image already downloaded: %s" % output_file)
        if not verify:
            return output_file
        image = ubunturelease.find_latest_release_image(
            version = version,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if image and ubunturelease.verify_image_checksum(
            iso_file = output_file,
            version = version,
            image = image,
            verify_signature = verify_signature,
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
    image = ubunturelease.find_latest_release_image(
        version = version,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not image:
        return None
    release_url = ubunturelease.get_release_listing_url(version) + image
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
        verified = ubunturelease.verify_image_checksum(
            iso_file = output_file,
            version = version,
            image = image,
            verify_signature = verify_signature,
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
    verify_signature = True,
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
            exit_on_failure = exit_on_failure)
        if overlay is None:
            return False

    # Make sure there is somewhere to write to. The download lands beside the
    # image, so a missing directory otherwise surfaces as a curl failure after
    # it has already fetched some of a three gigabyte file.
    output_dir = paths.get_filename_directory(output_file)
    success = fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to create output directory: %s" % output_dir)
        return False

    # Get the stock image
    version = profile.get("version")
    if not download_file:
        download_file = paths.join_paths(output_dir, "ubuntu-server-%s.iso" % version)
    stock_image = obtain_source_image(
        output_file = download_file,
        version = version,
        source_file = source_file,
        verify = verify,
        verify_signature = verify_signature,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not stock_image:
        return False

    # Work somewhere disposable
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as work_dir:
        if not work_dir:
            logger.log_error("Unable to create temporary directory")
            return False
        iso_dir = paths.join_paths(work_dir, "iso")

        # Take the image apart
        success = iso.extract_buildable_iso_tree(
            iso_file = stock_image,
            extract_dir = iso_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = iso.extract_iso_boot_images(
            iso_file = stock_image,
            extract_dir = work_dir,
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

        # Put it back together, still bootable both ways
        success = iso.create_bootable_iso(
            iso_file = output_file,
            source_dir = iso_dir,
            volume_name = ubunturelease.get_volume_name(version),
            bios_boot_image = BIOS_BOOT_IMAGE,
            efi_boot_image = iso.get_iso_efi_boot_image(work_dir),
            mbr_image = iso.get_iso_mbr_image(work_dir),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    logger.log_info("Built autoinstall image: %s" % output_file)
    return True
