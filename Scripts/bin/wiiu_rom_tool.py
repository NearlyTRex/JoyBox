#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.nintendo as nintendo
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Decrypt or test-decrypt Nintendo Wii U NUS packages.",
    details = (
        "A NUS package is a directory holding `title.tmd`, `title.tik` and the encrypted\n"
        "`.app`/`.h3` content files. The tool finds every `title.tik` under the input path and\n"
        "treats its directory as one package.\n"
        "\n"
        "`-r` runs CDecrypt inside the package directory, which writes the decrypted title\n"
        "(`code`, `content` and `meta` folders) alongside the encrypted files. With `-d`, the\n"
        "package's `.app`, `.h3`, `.tik`, `.tmd` and `.cert` files are then deleted, leaving\n"
        "only the decrypted title.\n"
        "\n"
        "`-e` copies each package to a temporary directory and decrypts the copy there to check\n"
        "that CDecrypt accepts it; the package itself is not changed."),
    examples = [
        ("Test that every package in a folder decrypts", "wiiu_rom_tool -i /path/to/wiiu -e"),
        ("Decrypt every package in place", "wiiu_rom_tool -i /path/to/wiiu -r"),
        ("Decrypt and remove the encrypted files, previewing first", "wiiu_rom_tool -i /path/to/wiiu -r -d -p -v"),
    ],
    notes = [
        "Without `-r` or `-e` nothing is done. If both are given, `-r` wins.",
        "`-e` copies the whole package, so the temporary directory needs room for it plus the decrypted output.",
        "CDecrypt must be installed as a JoyBox tool.",
    ],
    see_also = ["3ds_rom_tool", "switch_rom_tool"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A directory searched recursively for NUS packages (directories holding `title.tik`); must exist")
parser.add_boolean_argument(args = ("-r", "--decrypt_nus"), description = "Decrypt each package into its own directory with CDecrypt")
parser.add_boolean_argument(args = ("-e", "--verify_nus"), description = "Decrypt a temporary copy of each package to check it, leaving the package unchanged")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "With `-r`, delete the package's `.app`, `.h3`, `.tik`, `.tmd` and `.cert` files after decrypting")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Determine action
    action = "Decrypt NUS" if args.decrypt_nus else "Verify NUS" if args.verify_nus else None

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action
        ]
        if args.delete_originals:
            details.append("Delete originals: %s" % args.delete_originals)
        if not prompts.prompt_for_preview("Wii U ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".tik"]):
        if file.endswith("title.tik"):
            current_file = file
            current_file_dir = paths.get_filename_directory(current_file)
            current_file_basename = paths.get_filename_basename(current_file)

            # Decrypt NUS package
            if args.decrypt_nus:
                nintendo.decrypt_wiiu_nus_package(
                    nus_package_dir = current_file_dir,
                    delete_original = args.delete_originals,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

            # Verify NUS package
            elif args.verify_nus:
                nintendo.verify_wiiu_nus_package(
                    nus_package_dir = current_file_dir,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
