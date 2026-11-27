# Imports
from joybox import config
from joybox import system
from joybox import syncremotes
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts
from joybox import lockerauth

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "locker_auth_tool")
    parser.add_enum_argument(args = ("-l", "--locker_type"), arg_type = config.LockerType, default = config.LockerType.GDRIVE, description = "Remote locker to sign in")
    parser.add_string_argument(args = ("--client_file"), description = "JSON file downloaded for a Desktop app OAuth client; without it the stored client is used")
    parser.add_string_argument(args = ("--folder_id"), description = "Id or URL of the Drive folder the locker is kept in; without it the stored folder is used")
    parser.add_boolean_argument(args = ("--no_browser"), description = "Print the sign-in link instead of opening a browser")
    parser.add_common_arguments()
    return parser

# Sign the locker in and store its options
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get the remote, where its options are kept, and what to sign in with
    remote = lockerauth.get_locker_remote(args.locker_type)
    reference = lockerauth.get_options_reference(args.locker_type) if remote else None
    if not reference:
        return False
    options = lockerauth.read_stored_options(reference) if not args.client_file or not args.folder_id else {}
    client = lockerauth.choose_client(args.client_file, options)
    folder_id = lockerauth.choose_folder(args.folder_id, options) if client else None
    if not folder_id:
        return False

    # Show preview
    details = ["Remote: %s:%s" % (remote[1], remote[2]), "Client: %s" % client[0], "Folder: %s" % folder_id, "Store: %s" % reference]
    if not args.no_preview and not prompts.prompt_for_preview("Authorize %s" % args.locker_type, details):
        logger.log_warning("Operation cancelled by user")
        return None
    if args.pretend_run:
        syncremotes.authorize_remote(remote[0], client[0], client[1], open_browser = not args.no_browser, pretend_run = True)
        return True
    return lockerauth.sign_in_locker(
        locker_type = args.locker_type,
        remote = remote,
        reference = reference,
        options = options,
        client = client,
        folder_id = folder_id,
        open_browser = not args.no_browser,
        verbose = args.verbose)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
