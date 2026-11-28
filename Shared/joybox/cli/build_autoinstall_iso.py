# Imports
from joybox import autoinstall
from joybox import arguments
from joybox import setup
from joybox import system

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "build_autoinstall_iso")
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
    return parser

# Build a self-installing Ubuntu Server image from the ini's autoinstall profile and command-line overrides, or only show the config it produces
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get the profile, with anything given on the command line taking over
    profile = autoinstall.get_install_profile_with_overrides(
        release = args.release,
        hostname = args.hostname,
        serial_console = args.serial_console)

    # Show what the configuration produces, without downloading an image
    if args.show_seed:
        return autoinstall.show_install_seed(
            profile = profile,
            overlay_file = args.overlay,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Build the image, by default where the command was run
    return autoinstall.build_autoinstall_image_in_directory(
        output_dir = parser.get_output_path(check_exists = False),
        output_name = args.output_name,
        profile = profile,
        source_file = args.source_iso,
        overlay_file = args.overlay,
        user_data_file = args.user_data,
        verify = not args.skip_verify,
        verify_signature = not args.skip_signature,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
