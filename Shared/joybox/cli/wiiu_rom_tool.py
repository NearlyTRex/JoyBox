# Imports
from joybox import system
from joybox.nintendo import wiiu
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "wiiu_rom_tool")
    parser.add_input_path_argument(description = "A directory searched recursively for NUS packages (directories holding `title.tik`); must exist")
    parser.add_boolean_argument(args = ("-r", "--decrypt_nus"), description = "Decrypt each package into its own directory with CDecrypt")
    parser.add_boolean_argument(args = ("-e", "--verify_nus"), description = "Decrypt a temporary copy of each package to check it, leaving the package unchanged")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "With `-r`, delete the package's `.app`, `.h3`, `.tik`, `.tmd` and `.cert` files after decrypting")
    parser.add_common_arguments()
    return parser

# After a preview, decrypt or test-decrypt each Wii U NUS package under the input with CDecrypt
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

    # Decrypt or verify the packages
    wiiu.process_wiiu_nus_packages(
        input_path = input_path,
        decrypt = args.decrypt_nus,
        verify = args.verify_nus,
        delete_originals = args.delete_originals,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
