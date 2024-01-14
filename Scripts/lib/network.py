# Imports
import os, os.path
import sys
import getpass
import time

# Local imports
import config
import command
import sandbox
import system
import environment
import archive
import programs
import installer
import webpage
import registry

###########################################################
# Info
###########################################################

# Check if url is reachable
def IsUrlReachable(url):
    try:
        import requests
        get = requests.get(url)
        if get.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        return False

# Get remote json
def GetRemoteJson(url, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Processing GET request to '%s'" % url)
        import requests
        get = requests.get(url, headers={"Accept": "application/json"})
        if get.status_code == 200:
            return get.json()
        return None
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to process GET request to '%s'" % url)
            system.LogError(e)
            sys.exit(1)
        return None

# Post remote json
def PostRemoteJson(url, json_data, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Processing POST request to '%s'" % url)
        import requests
        post = requests.post(url, json = json_data)
        if post.status_code == 200:
            return post.json()
        return None
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to process POST request to '%s'" % url)
            system.LogError(e)
            sys.exit(1)
        return None

###########################################################
# Downloading
###########################################################

# Download url to local dir
def DownloadUrl(url, output_dir = None, output_file = None, verbose = False, exit_on_failure = False):

    # Get tool
    download_tool = None
    if programs.IsToolInstalled("Curl"):
        download_tool = programs.GetToolProgram("Curl")
    if not download_tool:
        system.LogError("Curl was not found")
        return False

    # Get download command
    download_cmd = [
        download_tool,
        "-L"
    ]
    if output_dir:
        download_cmd += [
            "--output-dir", output_dir,
            "-O"
        ]
    elif output_file:
        download_cmd += [
            "--output", output_file
        ]
    download_cmd += [url]

    # Create output directory
    if output_dir:
        system.MakeDirectory(output_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [download_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Download of %s failed" % url)
        return False

    # Check result
    if output_dir:
        for obj in system.GetDirectoryContents(output_dir):
            obj_path = os.path.join(output_dir, obj)
            if os.path.isfile(obj_path) and obj.endswith(system.GetFilenameFile(url)):
                return True
    elif output_file:
        return os.path.isfile(output_file)
    return False

# Download git url
def DownloadGitUrl(url, output_dir, clean_first = False, verbose = False, exit_on_failure = False):

    # Clear output dir
    if clean_first:
        system.ChmodFileOrDirectory(
            src = output_dir,
            perms = 777,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.RemoveDirectoryContents(
            dir = output_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Check output dir
    if os.path.isdir(output_dir) and system.DoesDirectoryContainFiles(output_dir):
        return True

    # Get tool
    download_tool = None
    if programs.IsToolInstalled("Git"):
        download_tool = programs.GetToolProgram("Git")
    if not download_tool:
        system.LogError("Git was not found")
        return False

    # Get download command
    download_cmd = [
        download_tool,
        "clone",
        "--recursive",
        url,
        output_dir
    ]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            cwd = os.path.expanduser("~"),
            blocking_processes = [download_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Git download of %s failed" % url)
        return False

    # Check result
    return system.DoesDirectoryContainFiles(output_dir)

###########################################################
# Shares
###########################################################

# Determine if network share is mounted
def IsNetworkShareMounted(mount_dir, base_location, network_share):

    # Windows
    if environment.IsWindowsPlatform():
        return os.path.isdir(mount_dir) and not system.IsDirectoryEmpty(mount_dir)

    # Linux
    elif environment.IsLinuxPlatform():
        mount_lines = command.RunOutputCommand(
            cmd = ["mount"])
        for line in mount_lines.split("\n"):
            if line.startswith("//%s/%s" % (base_location, network_share)):
                if mount_dir in line:
                    return True
        return False

    # Network share was not mounted
    return False

# Mount network share
def MountNetworkShare(mount_dir, base_location, network_share, username, password, verbose = False, exit_on_failure = False):

    # Windows
    if environment.IsWindowsPlatform():

        # Check if already mounted
        if os.path.isdir(mount_dir):
            return True

        # Get mount command
        mount_cmd = [
            "net",
            "use",
            "%s:" % system.GetDirectoryDrive(mount_dir),
            "\\\\%s\\%s" % (base_location, network_share),
            "/USER:%s" % username,
            password
        ]

        # Run mount command
        command.RunCheckedCommand(
            cmd = mount_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return True

    # Linux
    elif environment.IsLinuxPlatform():

        # Get mkdir command
        mkdir_cmd = [
            "sudo",
            "mkdir",
            "-p",
            mount_dir
        ]

        # Run mkdir command
        command.RunCheckedCommand(
            cmd = mkdir_cmd,
            verbose = verbose)

        # Check if already mounted
        if not system.IsDirectoryEmpty(mount_dir):
            return True

        # Get mount command
        mount_cmd = [
            "sudo",
            "mount",
            "-t", "cifs",
            "-o", "username=%s,password=%s,uid=%s,gid=%s" % (username, password, os.geteuid(), os.getegid()),
            "//%s/%s" % (base_location, network_share),
            "%s" % mount_dir
        ]

        # Run mount command
        command.RunCheckedCommand(
            cmd = mount_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return True

    # Network share was not mounted
    return False

###########################################################
# Github
###########################################################

# Get github repository
def GetGithubRepository(
    github_user,
    github_repo,
    github_token = None,
    verbose = False,
    exit_on_failure = False):
    try:
        import github
        if verbose:
            system.Log("Getting github repository '%s/%s'" % (github_user, github_repo))
        access = github.Github(github_token)
        repo = access.get_repo("%s/%s" % (github_user, github_repo))
        return repo
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to get github repository '%s/%s'" % (github_user, github_repo))
            system.LogError(e)
            sys.exit(1)
        return None

# Get github repositories
def GetGithubRepositories(
    github_user,
    github_token = None,
    exclude_forks = False,
    exclude_private = False,
    verbose = False,
    exit_on_failure = False):
    try:
        import github
        if verbose:
            system.Log("Getting github repositories for '%s'" % github_user)
        access = github.Github(github_token)
        user = access.get_user(github_user)
        repositories = []
        for repo in user.get_repos():
            if exclude_forks and repo.fork:
                continue
            if exclude_private and repo.private:
                continue
            repositories.append(repo)
        return repositories
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to get github repositories for '%s'" % github_user)
            system.LogError(e)
            sys.exit(1)
        return []

# Download github repository
def DownloadGithubRepository(
    github_user,
    github_repo,
    github_token = None,
    output_dir = "",
    clean_first = False,
    verbose = False,
    exit_on_failure = False):
    github_url = "https://github.com/%s/%s.git" % (github_user, github_repo)
    if github_token and isinstance(github_token, str) and len(github_token):
        github_url = "https://%s@github.com/%s/%s.git" % (github_token, github_user, github_repo)
    return DownloadGitUrl(
        url = github_url,
        output_dir = output_dir,
        clean_first = clean_first,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Archive github repository
def ArchiveGithubRepository(
    github_user,
    github_repo,
    github_token = None,
    output_file = "",
    clean_first = False,
    verbose = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Download repository
    success = DownloadGithubRepository(
        github_user = github_user,
        github_repo = github_repo,
        github_token = github_token,
        output_dir = tmp_dir_result,
        clean_first = clean_first,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Archive repository
    success = archive.CreateZipFromFolder(
        zip_file = output_file,
        source_dir = tmp_dir_result,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Check result
    return os.path.exists(output_file)