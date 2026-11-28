# Imports
from joybox import config
from joybox import system
from joybox import cryption
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "crypt_tool")
    parser.add_input_path_argument(description = "File, or directory of files, to encrypt or decrypt; must exist")
    parser.add_enum_argument(
        args = ("-t", "--passphrase_type"),
        arg_type = config.PassphraseType,
        description = "Which configured passphrase to use: `General` (`general_passphrase`) or `Locker` (`locker_passphrase`)")
    parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Encrypt each file to `<md5 of name>.enc` beside it")
    parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt each `.enc` file back to its stored original name beside it")
    parser.add_boolean_argument(args = ("-k", "--keep_originals"), description = "Keep the original files instead of deleting them after processing")
    parser.add_common_arguments()
    return parser

# After a preview, GPG-encrypt or decrypt the input file or tree in place with the passphrase from the config
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Check direction
    action = cryption.get_crypt_action(args.encrypt, args.decrypt)
    if not action:
        logger.log_error_and_quit("Give -e to encrypt or -d to decrypt")

    # Get passphrase
    passphrase = cryption.get_configured_passphrase(args.passphrase_type)

    # Show preview
    details = ["Path: %s" % input_path, "Action: %s" % action, "Keep originals: %s" % args.keep_originals]
    if not prompts.confirm_preview(args.no_preview, "%s files" % action, details):
        return

    # Encrypt or decrypt files
    cryption.crypt_files_in_place(
        src = input_path,
        passphrase = passphrase,
        encrypt = args.encrypt,
        decrypt = args.decrypt,
        delete_original = not args.keep_originals,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
