#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import network
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Github tool.")
parser.add_argument("-a", "--action",
    choices=[
        "archive",
        "update"
    ],
    default="archive", help="Github action"
)
parser.add_argument("-u", "--github_username", type=str, help="Github username")
parser.add_argument("-t", "--github_access_token", type=str, help="Github access token")
parser.add_argument("-d", "--archive_base_dir", type=str, default=environment.GetLockerDevelopmentArchivesRootDir(), help="Archive base directory")
parser.add_argument("-i", "--include_repos", type=str, default="", help="Only include these repos (comma delimited)")
parser.add_argument("-e", "--exclude_repos", type=str, default="", help="Use all repos except these (comma delimited)")
parser.add_argument("-f", "--force", action="store_true", help="Force action")
parser.add_argument("-r", "--recursive", action="store_true", help="Use recursion")
parser.add_argument("-c", "--clean", action="store_true", help="Use cleaning first")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get archive base directory
archive_base_dir = ""
if args.action == "archive":
    archive_base_dir = os.path.realpath(args.archive_base_dir)
    if not os.path.exists(archive_base_dir):
        system.LogError("Archive base dir '%s' does not exist" % args.archive_base_dir)
        sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

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
        exit_on_failure = args.exit_on_failure)

    # Archive repositories
    if args.action == "archive":
        for github_repository in github_repositories:
            success = network.ArchiveGithubRepository(
                github_user = github_username,
                github_repo = github_repository.name,
                github_token = github_access_token,
                output_dir = os.path.join(archive_base_dir, github_username, github_repository.name),
                recursive = args.recursive,
                clean = args.clean,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                break

    # Update repositories
    elif args.action == "update":
        for github_repository in github_repositories:
            if github_repository.fork:
                success = network.UpdateGithubRepository(
                    github_user = github_username,
                    github_repo = github_repository.name,
                    github_branch = github_repository.default_branch,
                    github_token = github_access_token,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    break

# Start
main()
