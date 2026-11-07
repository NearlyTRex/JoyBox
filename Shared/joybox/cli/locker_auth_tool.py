# Imports
import joybox.config as config
import joybox.system as system
import joybox.sync as sync
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts
import joybox.lockerauth as lockerauth

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Sign a remote locker in to Google Drive with your own OAuth client and store the result in 1Password.",
        details = (
            "Runs `rclone authorize` with the client, checks the new token can list the locker\n"
            "folder, then writes `client_id`, `client_secret`, `token` and `root_folder_id` to the\n"
            "1Password field `locker_<name>_config` references. Other stored options are kept,\n"
            "apart from a service account's. The client and token never reach a command line.\n"
            "\n"
            "Creating the client, once, in the Google Cloud console:\n"
            "\n"
            "1. Create a project and enable the Google Drive API.\n"
            "2. On Google Auth Platform > Branding, set an app name, support email, home page and\n"
            "   privacy policy URLs, and add their domain to the authorized domains. Leave the logo\n"
            "   empty: a logo needs Google's verification.\n"
            "3. On Audience, choose External and Publish app, so it is In production. A Testing\n"
            "   app's refresh tokens expire after 7 days. The app needs no verification.\n"
            "4. On Clients, create a Desktop app client and download its JSON for `--client_file`.\n"
            "\n"
            "When signing in, choose Advanced > Go to your app (or Continue) on the \"Google hasn't\n"
            "verified this app\" page."),
        examples = [
            ("Sign the Gdrive locker in to a folder", "locker_auth_tool --client_file ~/Downloads/client_secret.json --folder_id https://drive.google.com/drive/folders/1AbCdEf"),
            ("Sign in again with the stored client and folder, printing the link", "locker_auth_tool --no_browser"),
        ],
        notes = [
            "`locker_<name>_config` must be a 1Password reference in JoyBox.ini, such as `op://Personal/JoyBox/UserData.Share/locker_gdrive_config`; a missing field is created.",
            "Nothing is stored when the sign-in fails or the token cannot list the folder. Delete the client file once it is stored.",
            "The 1Password item is written back whole, so it must not hold a passkey, which the edit would drop.",
            "If Google answers with an error page, open the link in a private window, or wait a few minutes after publishing the app.",
        ],
        see_also = ["sync_tool", "master_backup"],
        section = "Backups & Lockers")
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
    args, unknown = parser.parse_known_args()

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
        return
    if args.pretend_run:
        sync.authorize_remote(remote[0], client[0], client[1], open_browser = not args.no_browser, pretend_run = True)
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
