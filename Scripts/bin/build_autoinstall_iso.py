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
    description = "Build an Ubuntu Server image that installs itself.")
parser.add_output_path_argument(description = "Directory to write the image into")
parser.add_string_argument(
    args = ("-n", "--output_name"),
    default = "ubuntu-autoinstall.iso",
    description = "Name of the image to write")
parser.add_string_argument(
    args = ("-s", "--source_iso"),
    description = "Stock Ubuntu Server image to start from, instead of downloading one")
parser.add_string_argument(
    args = ("-r", "--release"),
    description = "Ubuntu release to build from, overriding the configured one")
parser.add_string_argument(
    args = ("-t", "--hostname"),
    description = "Hostname for the installed machine, overriding the configured one")
parser.add_boolean_argument(
    args = ("-l", "--serial_console"),
    description = "Send installer output to the serial console as well")
parser.add_string_argument(
    args = ("-y", "--overlay"),
    description = "YAML file merged into the generated autoinstall config, for extra packages, snaps and commands")
parser.add_string_argument(
    args = ("-d", "--user_data"),
    description = "Use this cloud-init user-data file as it is, instead of generating one")
parser.add_boolean_argument(
    args = ("-w", "--show_seed"),
    description = "Print the seed this configuration produces and stop, without downloading anything")
parser.add_boolean_argument(
    args = ("-k", "--skip_verify"),
    description = "Skip checking the downloaded image against its published checksum")
parser.add_boolean_argument(
    args = ("-g", "--skip_signature"),
    description = "Skip checking who signed the published checksums")
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
