#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.autoinstall as autoinstall
import joybox.arguments as arguments
import joybox.logger as logger
import joybox.paths as paths
import joybox.setup as setup
import joybox.system as system

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Build an Ubuntu Server image that installs itself.",
    details = (
        "Downloads the newest point release of the configured Ubuntu Server version, adds a\n"
        "cloud-init seed that answers every installer question, and repacks it as an image\n"
        "that boots from a USB stick (BIOS and UEFI) or a disc. Write it to a stick, boot the\n"
        "target from it, and it installs without anyone at the keyboard.\n"
        "\n"
        "Everything the installer would ask comes from `[UserData.Autoinstall]` in\n"
        "`~/JoyBox.ini`: `autoinstall_version`, `autoinstall_username`, `autoinstall_realname`,\n"
        "`autoinstall_hostname`, `autoinstall_ssh_keys` (comma-separated public keys),\n"
        "`autoinstall_password_hash`, `autoinstall_locale`, `autoinstall_keyboard`,\n"
        "`autoinstall_timezone`, `autoinstall_packages`, `autoinstall_serial_console` and\n"
        "`autoinstall_overlay_file`. A build is refused unless there is a username the\n"
        "installer accepts, a hostname, and at least one of a password hash or an SSH key.\n"
        "Usernames the installer rejects only once it is running on the target, such as\n"
        "`admin` or `operator`, are refused here instead.\n"
        "\n"
        "The generated seed wipes the largest disk and lays it out as a 512 MB EFI partition\n"
        "plus an ext4 root, creates the account with passwordless sudo, installs and enables\n"
        "the SSH server with password logins disabled, and installs `autoinstall_packages`.\n"
        "With no password hash the account's password is locked rather than empty.\n"
        "\n"
        "Anything else the machine is for goes in an overlay: a YAML file merged into the\n"
        "generated document, written either as a whole `autoinstall:` document or as just its\n"
        "contents. Lists under `packages`, `snaps`, `early-commands`, `late-commands`, `users`,\n"
        "`write_files` and `runcmd` are appended to rather than replaced, dictionaries merge key\n"
        "by key, and plain values override. Late commands run in the installed system with the\n"
        "network up but without a running systemd; anything that needs systemd belongs in\n"
        "`user-data` `runcmd`, which runs on first boot. `Scripts/autoinstall/homelab_llm.yaml`\n"
        "is a worked example for a GPU LLM server.\n"
        "\n"
        "The download is checked against the `SHA256SUMS` published beside it, and that listing\n"
        "is checked with gpg against `autoinstall_signing_keyring`\n"
        "(`/usr/share/keyrings/ubuntu-archive-keyring.gpg` by default), including that the\n"
        "signing key is `autoinstall_signing_fingerprint` (the Ubuntu CD image signing key by\n"
        "default). A download that fails either check is deleted. The seed goes in `/nocloud`\n"
        "on the image, every boot entry gets `autoinstall ds=nocloud;s=/cdrom/nocloud/` before\n"
        "its `---` separator, and the boot menu waits 2 seconds."),
    examples = [
        ("Check the seed the configuration produces, without downloading", "build_autoinstall_iso --show_seed"),
        ("Check the seed with an overlay applied", "build_autoinstall_iso --show_seed -y Scripts/autoinstall/homelab_llm.yaml"),
        ("Build into the current directory", "build_autoinstall_iso"),
        ("Build elsewhere, with a name and a hostname for this machine", "build_autoinstall_iso -o ~/Images -n homelab.iso -t homelab"),
        ("Build the GPU LLM server image", "build_autoinstall_iso -y Scripts/autoinstall/homelab_llm.yaml -t llm -n llm.iso"),
        ("Build from an image already on disk", "build_autoinstall_iso -s ~/Downloads/ubuntu-24.04.1-live-server-amd64.iso"),
        ("Build from a complete cloud-init file of your own", "build_autoinstall_iso -d ~/JoyBox/Autoinstall/user-data"),
        ("Go through the build without downloading or writing anything", "build_autoinstall_iso -o ~/Images -p -v"),
    ],
    notes = [
        "Booting the image erases the target's largest disk without asking; there are 2 seconds at the boot menu to interrupt.",
        "Write it to a stick with `sudo dd if=ubuntu-autoinstall.iso of=/dev/sdX bs=4M status=progress conv=fsync`.",
        "The stock image is kept next to the output as `ubuntu-server-<version>.iso` and re-checked and reused by the next build. An image given with `--source_iso` is used as it is, without any check.",
        "If gpg or the keyring is missing the build stops rather than going on unverified; `--skip_signature` builds anyway, `--skip_verify` skips both checks.",
        "Make an SSH key with `ssh-keygen -t ed25519 -f ~/.ssh/joybox_autoinstall` and put the `.pub` contents in `autoinstall_ssh_keys`. Make a password hash with `mkpasswd --method=SHA-512` or `openssl passwd -6`; it only matters at the console.",
        "With `--user_data` the file is used exactly as written: no account checks, and neither the overlay nor the profile's packages are applied. Only the hostname still goes into `meta-data`.",
        "Needs Gpg and XorrISO from `setup_tools`. Try the image in `boot_vm_image` before writing it to a stick.",
    ],
    see_also = ["boot_vm_image", "setup_tools", "testvm"],
    section = "Servers & Machines")
parser.add_group("Output")
parser.add_output_path_argument(description = "Directory to write the image into, created if missing; the current directory when omitted")
parser.add_string_argument(
    args = ("-n", "--output_name"),
    default = "ubuntu-autoinstall.iso",
    description = "Filename of the image to write")
parser.add_group("Source image")
parser.add_string_argument(
    args = ("-s", "--source_iso"),
    description = "Stock Ubuntu Server image to start from instead of downloading one; used without verification")
parser.add_string_argument(
    args = ("-r", "--release"),
    description = "Ubuntu release to build from, such as `24.04`, instead of `autoinstall_version`; the newest point release of it is used")
parser.add_group("Seed")
parser.add_string_argument(
    args = ("-t", "--hostname"),
    description = "Hostname for the installed machine, instead of `autoinstall_hostname`")
parser.add_boolean_argument(
    args = ("-l", "--serial_console"),
    description = "Also send installer and kernel output to the serial console (`console=ttyS0`)")
parser.add_string_argument(
    args = ("-y", "--overlay"),
    description = "YAML file merged into the generated autoinstall config, for extra packages, snaps, files and commands; `autoinstall_overlay_file` when omitted")
parser.add_string_argument(
    args = ("-d", "--user_data"),
    description = "Complete cloud-init user-data file to use as it is, instead of generating one")
parser.add_boolean_argument(
    args = ("-w", "--show_seed"),
    description = "Print the user-data and meta-data this configuration produces, list what is missing, and stop without downloading anything")
parser.add_group("Verification")
parser.add_boolean_argument(
    args = ("-k", "--skip_verify"),
    description = "Do not check the downloaded image against its published checksum, nor the checksum's signature")
parser.add_boolean_argument(
    args = ("-g", "--skip_signature"),
    description = "Check the checksum but not who signed the published checksum listing")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get the profile, with anything given on the command line taking over
    profile = autoinstall.get_install_profile()
    if args.release:
        profile["version"] = args.release
    if args.hostname:
        profile["hostname"] = args.hostname
    if args.serial_console:
        profile["serial_console"] = True

    # Show what the configuration produces, without downloading an image
    if args.show_seed:
        problems = autoinstall.get_install_profile_problems(profile)
        for problem in problems:
            logger.log_error(problem)
        overlay = None
        overlay_file = args.overlay or profile.get("overlay_file")
        if overlay_file:
            overlay = autoinstall.read_overlay_file(
                overlay_file = overlay_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if overlay is None:
                return
        print(autoinstall.build_user_data(profile, overlay))
        print(autoinstall.build_meta_data(profile))
        if problems:
            logger.log_error("This configuration will not build until those are answered")
        return

    # Get the output path, defaulting to where the command was run
    output_dir = parser.get_output_path(check_exists = False)
    if not paths.is_path_valid(output_dir):
        output_dir = os.getcwd()
    output_file = paths.join_paths(output_dir, args.output_name)

    # Build the image
    success = autoinstall.build_autoinstall_image(
        output_file = output_file,
        source_file = args.source_iso,
        profile = profile,
        overlay_file = args.overlay,
        user_data_file = args.user_data,
        verify = not args.skip_verify,
        verify_signature = not args.skip_signature,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Unable to build autoinstall image")
        return

    # Say what to do with it
    logger.log_info("Write it to a usb stick with:")
    logger.log_info("  sudo dd if=%s of=/dev/sdX bs=4M status=progress conv=fsync" % output_file)
    logger.log_info(
        "Booting from it installs %s without asking anything (%d seconds to interrupt)."
        % (profile.get("hostname"), autoinstall.boot_timeout))

# Start
if __name__ == "__main__":
    system.run_main(main)
