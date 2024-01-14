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
        "archive"
    ],
    default="archive", help="Github action"
)
parser.add_argument("-u", "--github_username", type=str, help="Github username")
parser.add_argument("-n", "--github_repository", type=str, help="Github repository")
parser.add_argument("-t", "--github_access_token", type=str, help="Github access token")
parser.add_argument("-d", "--archive_dir", type=str, default=environment.GetSyncedDevelopmentArchiveDir(), help="Archive directory")
args, unknown = parser.parse_known_args()

# Check that archive dir exists first
archive_dir = ""
if args.action == "archive":
    archive_dir = os.path.realpath(args.archive_dir)
    if not os.path.exists(archive_dir):
        system.LogError("Archive dir '%s' does not exist" % args.archive_dir)
        sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Get github username
    github_username = args.github_username
    if not github_username:
        github_username = ini.GetIniValue("UserData.GitHub", "github_username")

    # Get github access token
    github_access_token = args.github_access_token
    if not github_access_token:
        github_access_token = ini.GetIniValue("UserData.GitHub", "github_access_token")

    # Get github repositories
    github_repositories = []
    if args.github_repository:
        github_repositories = [args.github_repository]
    if len(github_repositories) == 0:
        github_repositories = network.GetGithubRepositories(
            github_user = github_username,
            github_token = github_access_token,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Archive repositories
    if args.action == "archive":
        for github_repository in github_repositories:
            network.ArchiveGithubRepository(
                github_user = github_username,
                github_repo = github_repository.name,
                github_token = github_access_token,
                output_file = os.path.join(archive_dir, github_repository.name + "_" + str(environment.GetCurrentTimestamp()) + ".zip"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Start
main()
