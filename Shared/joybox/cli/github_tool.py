# Imports
from joybox import config
from joybox import environment
from joybox import system
from joybox import githubrepos
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "github_tool")
    parser.add_group("GitHub")
    parser.add_enum_argument(
        args = ("-a", "--action"),
        arg_type = config.GithubActionType,
        default = config.GithubActionType.ARCHIVE,
        description = "What to do with each repository: back it up as a zip, or merge upstream into a fork")
    parser.add_string_argument(args = ("-u", "--github_username"), description = "GitHub user whose repositories are used; `[UserData.GitHub] github_username` when omitted")
    parser.add_string_argument(args = ("-t", "--github_access_token"), description = "GitHub personal access token; `[UserData.GitHub] github_access_token` when omitted")
    parser.add_group("Output")
    parser.add_string_argument(
        args = ("-d", "--archive_base_dir"),
        default = environment.get_locker_development_archives_root_dir(),
        description = "Locker directory the archives go under, as `<dir>/<user>/<repo>/`; used by `Archive` only")
    parser.add_group("Selection")
    parser.add_string_argument(args = ("-i", "--include_repos"), default = "", description = "Comma-separated repository names to use, ignoring all others")
    parser.add_string_argument(args = ("-e", "--exclude_repos"), default = "", description = "Comma-separated repository names to leave out")
    parser.add_group("Archive")
    parser.add_boolean_argument(args = ("-f", "--force"), description = "Not used by either action")
    parser.add_boolean_argument(args = ("-r", "--recursive"), description = "Clone submodules too (`git clone --recursive`)")
    parser.add_boolean_argument(args = ("-c", "--clean"), description = "Leave the `.git` folder out of the zip")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.ALL,
        description = "Locker to back the zips up to")
    parser.add_common_arguments()
    return parser

# After a preview, archive each of the user's GitHub repositories into the locker as a zip, or sync each fork with its upstream
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get archive base directory
    archive_base_dir = ""
    if args.action == config.GithubActionType.ARCHIVE:
        archive_base_dir = parser.get_checked_path("archive_base_dir")

    # Archive or update the repositories
    githubrepos.run_github_action(
        action = args.action,
        github_username = args.github_username,
        github_access_token = args.github_access_token,
        archive_base_dir = archive_base_dir,
        include_repos = args.include_repos,
        exclude_repos = args.exclude_repos,
        recursive = args.recursive,
        clean = args.clean,
        locker_type = args.locker_type,
        show_preview = not args.no_preview,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
