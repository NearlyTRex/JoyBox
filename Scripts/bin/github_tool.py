#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import network
import ini
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Github tool.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.GithubActionType,
    default = config.GithubActionType.TREE,
    description = "Github action type")
parser.add_string_argument(args = ("-u", "--github_username"), description = "Github username")
parser.add_string_argument(args = ("-t", "--github_access_token"), description = "Github access token")
parser.add_string_argument(
    args = ("-d", "--archive_base_dir"),
    default = environment.GetLockerDevelopmentArchivesRootDir(),
    description = "Archive base directory")
parser.add_string_argument(args = ("-i", "--include_repos"), default = "", description = "Only include these repos (comma delimited)")
parser.add_string_argument(args = ("-e", "--exclude_repos"), default = "", description = "Use all repos except these (comma delimited)")
parser.add_boolean_argument(args = ("-f", "--force"), description = "Force action")
parser.add_boolean_argument(args = ("-r", "--recursive"), description = "Use recursion")
parser.add_boolean_argument(args = ("-c", "--clean"), description = "Use cleaning first")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get archive base directory
    archive_base_dir = ""
    if args.action == config.GithubActionType.ARCHIVE:
        archive_base_dir = parser.get_checked_path("archive_base_dir")

    # Get github username
    github_username = args.github_username
    if not github_username:
        github_username = ini.GetIniValue("UserData.GitHub", "github_username")

    # Get github access token
    github_access_token = args.github_access_token
    if not github_access_token:
        github_access_token = ini.GetIniValue("UserData.GitHub", "github_access_token")

    # Get include/exclude lists
    include_repos = []
    exclude_repos = []
    if len(args.include_repos):
        include_repos = args.include_repos.split(",")
    if len(args.exclude_repos):
        exclude_repos = args.exclude_repos.split(",")

    # Get github repositories
    github_repositories = network.GetGithubRepositories(
        github_user = github_username,
        github_token = github_access_token,
        include_repos = include_repos,
        exclude_repos = exclude_repos,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Archive repositories
    if args.action == config.GithubActionType.ARCHIVE:
        for github_repository in github_repositories:
            success = network.ArchiveGithubRepository(
                github_user = github_username,
                github_repo = github_repository.name,
                github_token = github_access_token,
                output_dir = system.JoinPaths(archive_base_dir, github_username, github_repository.name),
                recursive = args.recursive,
                clean = args.clean,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogWarning("Unable to archive repository %s" % github_repository.name)

    # Update repositories
    elif args.action == config.GithubActionType.UPDATE:
        for github_repository in github_repositories:
            if github_repository.fork:
                success = network.UpdateGithubRepository(
                    github_user = github_username,
                    github_repo = github_repository.name,
                    github_branch = github_repository.default_branch,
                    github_token = github_access_token,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogWarning("Unable to update repository %s" % github_repository.name)

# Start
if __name__ == "__main__":
    system.RunMain(main)
