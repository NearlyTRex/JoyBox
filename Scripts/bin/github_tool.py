#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.environment as environment
import joybox.system as system
import joybox.network as network
import joybox.settings as settings
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Archive your GitHub repositories into the locker, or sync your forks with upstream.",
    details = (
        "Lists the repositories owned by the GitHub user, public and private, optionally\n"
        "narrowed with `--include_repos` or `--exclude_repos`, and then runs one action on\n"
        "each.\n"
        "\n"
        "`Archive` clones each repository with Git into a temporary directory, zips it, tests\n"
        "the zip, and backs it up to the locker as\n"
        "`<archive_base_dir>/<user>/<repo>/<repo>_<timestamp>.zip`. Each run adds a new\n"
        "timestamped zip. With `--clean` the `.git` folder is left out, so the zip holds only\n"
        "the working tree.\n"
        "\n"
        "`Update` asks GitHub to merge the upstream changes into the default branch of each of\n"
        "your forks (the merge-upstream API). Repositories that are not forks are skipped.\n"
        "\n"
        "The username and access token come from `[UserData.GitHub] github_username` and\n"
        "`github_access_token` in `~/JoyBox.ini` unless given on the command line."),
    examples = [
        ("Archive every repository to all lockers", "github_tool"),
        ("Archive two repositories with their submodules", "github_tool -i \"JoyBox,Dotfiles\" -r"),
        ("Archive everything but one repository, without the git history, to the local locker", "github_tool -e LargeRepo -c -l Local"),
        ("Sync all forks with their upstream", "github_tool -a Update"),
        ("Preview an archive run", "github_tool -p -v"),
    ],
    notes = [
        "The token needs access to private repositories for them to be listed, and write access for `Update`.",
        "Repository names in `--include_repos` and `--exclude_repos` must match exactly, including case.",
        "A repository that fails to archive or update is reported and the rest still run.",
        "For `Archive`, `--archive_base_dir` must already exist and Git must be installed with `setup_tools`.",
    ],
    see_also = ["setup_tools", "backup_tool", "master_backup"],
    section = "Backups & Lockers")
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
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get archive base directory
    archive_base_dir = ""
    if args.action == config.GithubActionType.ARCHIVE:
        archive_base_dir = parser.get_checked_path("archive_base_dir")

    # Get github username
    github_username = args.github_username
    if not github_username:
        github_username = settings.get_value("UserData.GitHub", "github_username")

    # Get github access token
    github_access_token = args.github_access_token
    if not github_access_token:
        github_access_token = settings.get_value("UserData.GitHub", "github_access_token")

    # Get include/exclude lists
    include_repos = []
    exclude_repos = []
    if len(args.include_repos):
        include_repos = args.include_repos.split(",")
    if len(args.exclude_repos):
        exclude_repos = args.exclude_repos.split(",")

    # Get github repositories
    github_repositories = network.get_github_repositories(
        github_user = github_username,
        github_token = github_access_token,
        include_repos = include_repos,
        exclude_repos = exclude_repos,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Show preview
    if not args.no_preview:
        details = [
            "Action: %s" % args.action,
            "User: %s" % github_username,
            "Repositories: %d" % len(github_repositories)
        ]
        if args.action == config.GithubActionType.ARCHIVE:
            details.append("Archive dir: %s" % archive_base_dir)
        if not prompts.prompt_for_preview("GitHub %s" % args.action, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Archive repositories
    if args.action == config.GithubActionType.ARCHIVE:
        for github_repository in github_repositories:
            success = network.archive_github_repository(
                github_user = github_username,
                github_repo = github_repository.name,
                github_token = github_access_token,
                output_dir = paths.join_paths(archive_base_dir, github_username, github_repository.name),
                recursive = args.recursive,
                clean = args.clean,
                locker_type = args.locker_type,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if not success:
                logger.log_warning("Unable to archive repository %s" % github_repository.name)

    # Update repositories
    elif args.action == config.GithubActionType.UPDATE:
        for github_repository in github_repositories:
            if github_repository.fork:
                success = network.update_github_repository(
                    github_user = github_username,
                    github_repo = github_repository.name,
                    github_branch = github_repository.default_branch,
                    github_token = github_access_token,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    logger.log_warning("Unable to update repository %s" % github_repository.name)

# Start
if __name__ == "__main__":
    system.run_main(main)
