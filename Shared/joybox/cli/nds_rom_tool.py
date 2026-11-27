# Imports
from joybox import system
from joybox.nintendo import ds
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "nds_rom_tool")
    parser.add_input_path_argument(description = "An `.nds` file, or a directory searched recursively for them; must exist")
    parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt each ROM in place")
    parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Encrypt each ROM in place")
    parser.add_boolean_argument(args = ("-g", "--generate_hash"), description = "Also have NDecrypt write the ROM's size and hashes to a companion file")
    parser.add_common_arguments()
    return parser

# After a preview, decrypt or encrypt the secure area of each NDS ROM under the input in place with NDecrypt
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

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

    # Decrypt or encrypt the roms
    ds.process_nds_roms(
        input_path = input_path,
        decrypt = args.decrypt,
        encrypt = args.encrypt,
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
