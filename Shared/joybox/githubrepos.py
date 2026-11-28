# Imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import paths
from joybox import prompts
from joybox import settings

###########################################################
# GitHub repository archives and fork updates
###########################################################

# The given GitHub user and access token, each falling back to its [UserData.GitHub] setting
def resolve_github_credentials(github_username = None, github_access_token = None):
    if not github_username:
        github_username = settings.get_value("UserData.GitHub", "github_username")
    if not github_access_token:
        github_access_token = settings.get_value("UserData.GitHub", "github_access_token")
    return github_username, github_access_token

# The repository names of a comma-separated list; none for an empty list
def split_repository_names(repository_names):
    if len(repository_names):
        return repository_names.split(",")
    return []

# Preview the action on the repositories; False when the user declines
def _confirm_github_action(action, github_username, github_repositories, archive_base_dir):
    details = [
        "Action: %s" % action,
        "User: %s" % github_username,
        "Repositories: %d" % len(github_repositories)
    ]
    if action == config.GithubActionType.ARCHIVE:
        details.append("Archive dir: %s" % archive_base_dir)
    if not prompts.prompt_for_preview("GitHub %s" % action, details):
        logger.log_warning("Operation cancelled by user")
        return False
    return True

# Archive each repository as a zip under <archive_base_dir>/<user>/<repo>, warning about each one that fails
def archive_github_repositories(
    github_repositories,
    github_username,
    github_access_token,
    archive_base_dir,
    recursive = False,
    clean = False,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for github_repository in github_repositories:
        success = network.archive_github_repository(
            github_user = github_username,
            github_repo = github_repository.name,
            github_token = github_access_token,
            output_dir = paths.join_paths(archive_base_dir, github_username, github_repository.name),
            recursive = recursive,
            clean = clean,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_warning("Unable to archive repository %s" % github_repository.name)

# Merge upstream into each repository that is a fork, warning about each one that fails
def update_github_forks(github_repositories, github_username, github_access_token, verbose = False, pretend_run = False, exit_on_failure = False):
    for github_repository in github_repositories:
        if not github_repository.fork:
            continue
        success = network.update_github_repository(
            github_user = github_username,
            github_repo = github_repository.name,
            github_branch = github_repository.default_branch,
            github_token = github_access_token,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_warning("Unable to update repository %s" % github_repository.name)

# After an optional preview, archive each selected repository of the user into the locker as a
# zip, or sync each selected fork with its upstream
def run_github_action(
    action,
    github_username = None,
    github_access_token = None,
    archive_base_dir = "",
    include_repos = "",
    exclude_repos = "",
    recursive = False,
    clean = False,
    locker_type = None,
    show_preview = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    github_username, github_access_token = resolve_github_credentials(github_username, github_access_token)
    github_repositories = network.get_github_repositories(
        github_user = github_username,
        github_token = github_access_token,
        include_repos = split_repository_names(include_repos),
        exclude_repos = split_repository_names(exclude_repos),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if show_preview and not _confirm_github_action(action, github_username, github_repositories, archive_base_dir):
        return
    if action == config.GithubActionType.ARCHIVE:
        archive_github_repositories(
            github_repositories, github_username, github_access_token, archive_base_dir,
            recursive = recursive,
            clean = clean,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        update_github_forks(github_repositories, github_username, github_access_token, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
