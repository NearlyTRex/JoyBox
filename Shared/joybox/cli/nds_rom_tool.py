# Imports
import joybox.system as system
import joybox.nintendo as nintendo
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Decrypt or encrypt Nintendo DS ROMs in place with NDecrypt.",
        details = (
            "Finds every `.nds` file under the input path (or takes the one file given) and runs\n"
            "NDecrypt on it: `-d` decrypts the secure area, `-e` encrypts it again. NDecrypt\n"
            "rewrites each file in place, so no new files are created unless `-g` is given, which\n"
            "has NDecrypt write the file's size and hashes to a companion file."),
        examples = [
            ("Decrypt every DS ROM in a folder", "nds_rom_tool -i /path/to/nds -d"),
            ("Preview the decryption without changing anything", "nds_rom_tool -i /path/to/nds -d -p -v"),
            ("Encrypt one ROM and record its hashes", "nds_rom_tool -i \"/path/to/Game (USA).nds\" -e -g"),
        ],
        notes = [
            "Without `-d` or `-e` nothing is done. If both are given, `-d` wins.",
            "NDecrypt must be installed as a JoyBox tool.",
        ],
        see_also = ["3ds_rom_tool"],
        section = "Game ROMs & Images")
    parser.add_input_path_argument(description = "An `.nds` file, or a directory searched recursively for them; must exist")
    parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt each ROM in place")
    parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Encrypt each ROM in place")
    parser.add_boolean_argument(args = ("-g", "--generate_hash"), description = "Also have NDecrypt write the ROM's size and hashes to a companion file")
    parser.add_common_arguments()
    return parser

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Determine action
    action = "Decrypt" if args.decrypt else "Encrypt" if args.encrypt else None

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action
        ]
        if not prompts.prompt_for_preview("NDS ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".nds"]):
        current_file = file

        # Decrypt NDS file
        if args.decrypt:
            nintendo.decrypt_nds_rom(
                nds_file = current_file,
                generate_hash = args.generate_hash,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Encrypt NDS file
        elif args.encrypt:
            nintendo.encrypt_nds_rom(
                nds_file = current_file,
                generate_hash = args.generate_hash,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
