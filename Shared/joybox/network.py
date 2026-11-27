# Imports
import importlib
import ctypes
import os
import os.path
import tempfile
from ctypes import wintypes
from xml.parsers.expat import ExpatError

# Local imports
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import archive
from joybox import programs
from joybox import locker
from joybox import platform_info, runtime

# Get requests, imported on first use
def _get_requests():
    return importlib.import_module("requests")

# Get xmltodict, imported on first use
def _get_xmltodict():
    return importlib.import_module("xmltodict")

# Get github, imported on first use
def _get_github():
    return importlib.import_module("github")

# Seconds a plain HTTP request may take before it is abandoned
REQUEST_TIMEOUT_SECONDS = 10

# How often curl retries a transient download failure, and how long it waits to connect
DOWNLOAD_RETRIES = 3
DOWNLOAD_CONNECT_TIMEOUT_SECONDS = 30

###########################################################
# Info
###########################################################

# Check if url is reachable
# Query parameters go in params rather than the url, so a key among them never
# reaches a log line that names the url
def is_url_reachable(url, params = None, timeout = REQUEST_TIMEOUT_SECONDS):
    requests = _get_requests()
    try:
        get = requests.get(url, params=params, timeout=timeout)
        return get.status_code == 200
    except requests.RequestException:
        return False

# GET a URL and decode its JSON body; None on any non-200 answer or request error
def get_remote_json(
    url,
    headers = None,
    params = None,
    timeout = REQUEST_TIMEOUT_SECONDS,
    verbose = False,
    exit_on_failure = False):
    requests = _get_requests()
    try:
        if verbose:
            logger.log_info("Processing GET request to '%s'" % url)
        if not headers:
            headers = {"Accept": "application/json"}
        get = requests.get(url, headers=headers, params=params, timeout=timeout)
        if verbose:
            logger.log_info("Got response: %s" % str(get.status_code))
        if get.status_code == 200:
            return get.json()
        return None
    except requests.RequestException as e:
        if exit_on_failure:
            logger.log_error("Unable to process GET request to '%s'" % url)
            logger.log_error(e, quit_program = True)
        return None

# GET a URL and return its body text; None on any non-200 answer or request error
def get_remote_html(
    url,
    headers = None,
    timeout = REQUEST_TIMEOUT_SECONDS,
    verbose = False,
    exit_on_failure = False):
    requests = _get_requests()
    try:
        if verbose:
            logger.log_info("Processing GET request to '%s'" % url)
        if not headers:
            headers = {}
        get = requests.get(url, headers=headers, timeout=timeout)
        if verbose:
            logger.log_info("Got response: %s" % str(get.status_code))
        if get.status_code == 200:
            return get.text
        return None
    except requests.RequestException as e:
        if exit_on_failure:
            logger.log_error("Unable to process GET request to '%s'" % url)
            logger.log_error(e, quit_program = True)
        return None

# POST data as JSON and decode the JSON reply; None on a non-200 answer, request error or pretend run
def post_remote_json(
    url,
    headers = None,
    data = None,
    timeout = REQUEST_TIMEOUT_SECONDS,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if pretend_run:
        logger.log_info("Would POST to '%s'" % url)
        return None
    requests = _get_requests()
    try:
        if verbose:
            logger.log_info("Processing POST request to '%s'" % url)
        if not headers:
            headers = {"Accept": "application/json"}
        post = requests.post(url, headers=headers, json=data, timeout=timeout)
        if verbose:
            logger.log_info("Got response: %s" % str(post.status_code))
        if post.status_code == 200:
            return post.json()
        return None
    except requests.RequestException as e:
        if exit_on_failure:
            logger.log_error("Unable to process POST request to '%s'" % url)
            logger.log_error(e, quit_program = True)
        return None

# GET a URL and parse its XML body into a dict; None on a non-200 answer, request or parse error
def get_remote_xml(
    url,
    headers = None,
    timeout = REQUEST_TIMEOUT_SECONDS,
    verbose = False,
    exit_on_failure = False):
    requests = _get_requests()
    xmltodict = _get_xmltodict()
    try:
        if verbose:
            logger.log_info("Processing GET request to '%s'" % url)
        if not headers:
            headers = {"Accept": "text/xml"}
        get = requests.get(url, headers=headers, timeout=timeout)
        if verbose:
            logger.log_info("Got response: %s" % str(get.status_code))
        if get.status_code == 200:
            return xmltodict.parse(get.text)
        return None
    except (requests.RequestException, ExpatError) as e:
        if exit_on_failure:
            logger.log_error("Unable to process GET request to '%s'" % url)
            logger.log_error(e, quit_program = True)
        return None

###########################################################
# Downloading
###########################################################

# Curl command that follows redirects into output_dir under the remote name, or to output_file
def build_curl_download_cmd(download_tool, url, output_dir, output_file, retries, connect_timeout):
    download_cmd = [
        download_tool,
        "-L",
        "--retry", str(retries),
        "--connect-timeout", str(connect_timeout)
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
    return download_cmd

# Whether the download landed: a file in output_dir ending with the url's file name, or output_file itself
def is_url_downloaded(url, output_dir, output_file):
    if output_dir:
        for obj in paths.get_directory_contents(output_dir):
            obj_path = paths.join_paths(output_dir, obj)
            if paths.is_path_file(obj_path) and obj.endswith(paths.get_filename_file(url)):
                return True
    elif output_file:
        return paths.is_path_file(output_file)
    return False

# Run a download command, logging the failure message when it exits nonzero; True on success
def run_download_command(download_cmd, options, failure_message, verbose = False, pretend_run = False, exit_on_failure = False):
    code = command.run_returncode_command(
        cmd = download_cmd,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error(failure_message)
        return False
    return True

# Download url to local dir
def download_url(
    url,
    output_dir = None,
    output_file = None,
    retries = DOWNLOAD_RETRIES,
    connect_timeout = DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    download_tool = programs.find_tool_program("Curl")
    if not download_tool:
        return False

    # Get download command
    download_cmd = build_curl_download_cmd(download_tool, url, output_dir, output_file, retries, connect_timeout)

    # Create output directory
    if output_dir:
        fileops.make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run download command
    options = commandbase.create_command_options(
        blocking_processes = [download_tool])
    if not run_download_command(download_cmd, options, "Download of %s failed" % url, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
        return False

    # A pretend run downloads nothing, so there is nothing to check
    if pretend_run:
        return True

    # Check result
    return is_url_downloaded(url, output_dir, output_file)

# Open up and empty an existing clone directory so it can be cloned into afresh
def clear_git_output_dir(output_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    fileops.chmod_file_or_directory(
        src = output_dir,
        perms = 777,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    fileops.remove_directory_contents(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Git clone command for url into output_dir, with the branch and submodule options
def build_git_clone_cmd(download_tool, url, output_dir, branch, recursive):
    download_cmd = [
        download_tool,
        "clone"
    ]
    if branch:
        download_cmd += ["--branch", branch]
    if recursive:
        download_cmd += ["--recursive"]
    download_cmd += [
        url,
        output_dir
    ]
    return download_cmd

# Clone a repo into output_dir with Git, optionally wiping it first; True without cloning when it already has files
def download_git_url(
    url,
    output_dir,
    branch = None,
    recursive = True,
    clean = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Clear output dir
    if clean and paths.is_path_directory(output_dir):
        clear_git_output_dir(output_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Check output dir
    if paths.is_path_directory(output_dir) and paths.does_directory_contain_files(output_dir):
        return True

    # Get tool
    download_tool = programs.find_tool_program("Git")
    if not download_tool:
        return False

    # Get download command
    download_cmd = build_git_clone_cmd(download_tool, url, output_dir, branch, recursive)

    # Run download command
    options = commandbase.create_command_options(
        cwd = os.path.expanduser("~"),
        blocking_processes = [download_tool])
    if not run_download_command(download_cmd, options, "Git download of %s failed" % url, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
        return False

    # A pretend run clones nothing, so there is nothing to check
    if pretend_run:
        return True

    # Check result
    return paths.does_directory_contain_files(output_dir)

###########################################################
# Shares
###########################################################

# Determine if network share is mounted
def is_network_share_mounted(mount_dir, base_location, network_share):

    # Windows
    if platform_info.is_windows_platform():
        return paths.is_path_directory(mount_dir) and not paths.is_directory_empty(mount_dir)

    # Linux
    if platform_info.is_linux_platform():
        mount_lines = command.run_output_command(
            cmd = ["mount"])
        share_source = "//%s/%s" % (base_location, network_share)
        share_target = os.path.normpath(mount_dir)
        for line in mount_lines.split("\n"):
            source, on, rest = line.partition(" on ")
            target = rest.rsplit(" type ", 1)[0]
            if on and source == share_source and os.path.normpath(target) == share_target:
                return True
        return False

    # Network share was not mounted
    return False

# Map a windows drive to a share, passing the password in-process rather than on a command line
def map_windows_drive(drive, remote, username, password):
    class NETRESOURCE(ctypes.Structure):
        _fields_ = [
            ("dwScope", wintypes.DWORD),
            ("dwType", wintypes.DWORD),
            ("dwDisplayType", wintypes.DWORD),
            ("dwUsage", wintypes.DWORD),
            ("lpLocalName", wintypes.LPWSTR),
            ("lpRemoteName", wintypes.LPWSTR),
            ("lpComment", wintypes.LPWSTR),
            ("lpProvider", wintypes.LPWSTR),
        ]

    resource = NETRESOURCE(
        dwType = 1,  # RESOURCETYPE_DISK
        lpLocalName = drive,
        lpRemoteName = remote)
    return ctypes.windll.mpr.WNetAddConnection2W(ctypes.byref(resource), password, username, 0)

# Directory for mount.cifs credentials; a comma would split the -o option string
def get_cifs_credentials_dir():
    tmp_dir = tempfile.gettempdir()
    return "/tmp" if "," in tmp_dir else tmp_dir

# Write a mount.cifs credentials file readable only by its owner
def write_cifs_credentials(username, password):
    fd, credentials_file = tempfile.mkstemp(prefix = "joybox-cifs-", suffix = ".cred", dir = get_cifs_credentials_dir())
    with os.fdopen(fd, "w") as handle:
        handle.write("username=%s\npassword=%s\n" % (username, password))
    return credentials_file

# Map the share to mount_dir's drive letter; True when the directory already exists
def mount_windows_network_share(
    mount_dir,
    base_location,
    network_share,
    username,
    password,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if already mounted
    if paths.is_path_directory(mount_dir):
        return True

    # Map drive
    drive = "%s:" % paths.get_directory_drive(mount_dir)
    remote = "\\\\%s\\%s" % (base_location, network_share)
    if verbose:
        logger.log_info("Mapping %s to %s" % (drive, remote))
    if pretend_run:
        return True
    code = map_windows_drive(drive, remote, username, password)
    if code != 0:
        logger.log_error("Unable to map %s to %s (error %d)" % (drive, remote, code), quit_program = exit_on_failure)
        return False
    return True

# Sudo-mount the share at mount_dir over CIFS as the current user, reading the credentials file; True on success
def mount_cifs_share(
    mount_dir,
    base_location,
    network_share,
    credentials_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get mount command
    mount_cmd = [
        "sudo",
        "mount",
        "-t", "cifs",
        "-o", "credentials=%s,uid=%s,gid=%s" % (credentials_file, os.geteuid(), os.getegid()),
        "//%s/%s" % (base_location, network_share),
        "%s" % mount_dir
    ]

    # Run mount command
    code = command.run_returncode_command(
        cmd = mount_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Create mount_dir and sudo-mount the share there over CIFS with a temporary credentials file; True when already mounted
def mount_linux_network_share(
    mount_dir,
    base_location,
    network_share,
    username,
    password,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make mount directory
    code = command.run_returncode_command(
        cmd = ["sudo", "mkdir", "-p", mount_dir],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check if already mounted
    if is_network_share_mounted(mount_dir, base_location, network_share):
        return True

    # Keep the password off the command line; a pretend run writes nothing
    if pretend_run:
        credentials_file = paths.join_paths(get_cifs_credentials_dir(), "joybox-cifs-pretend.cred")
    else:
        credentials_file = write_cifs_credentials(username, password)
    try:
        return mount_cifs_share(
            mount_dir, base_location, network_share, credentials_file,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    finally:
        if not pretend_run:
            fileops.remove_file(credentials_file)

# Mount an SMB share at mount_dir, as a mapped drive on Windows or a sudo CIFS mount on Linux; True when already mounted
def mount_network_share(
    mount_dir,
    base_location,
    network_share,
    username,
    password,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Credentials containing a line break cannot be expressed to either platform
    if "\n" in username or "\n" in password:
        logger.log_error("Share credentials must not contain line breaks", quit_program = exit_on_failure)
        return False

    # Windows
    if platform_info.is_windows_platform():
        return mount_windows_network_share(
            mount_dir, base_location, network_share, username, password,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Linux
    if platform_info.is_linux_platform():
        return mount_linux_network_share(
            mount_dir, base_location, network_share, username, password,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Network share was not mounted
    return False

###########################################################
# Github
###########################################################

# Repository object for user/repo from the GitHub API; None on an API error
def get_github_repository(
    github_user,
    github_repo,
    github_token = None,
    verbose = False,
    exit_on_failure = False):
    github = _get_github()
    try:
        if verbose:
            logger.log_info("Getting github repository '%s/%s'" % (github_user, github_repo))
        gh = github.Github(github_token)
        repo = gh.get_repo("%s/%s" % (github_user, github_repo))
        return repo
    except (github.GithubException, OSError) as e:
        if exit_on_failure:
            logger.log_error("Unable to get github repository '%s/%s'" % (github_user, github_repo))
            logger.log_error(e, quit_program = True)
        return None

# Repositories the token's user owns under github_user, filtered by the include, exclude, fork and private options
def get_github_repositories(
    github_user,
    github_token = None,
    include_repos = (),
    exclude_repos = (),
    exclude_forks = False,
    exclude_private = False,
    verbose = False,
    exit_on_failure = False):
    github = _get_github()
    try:
        if verbose:
            logger.log_info("Getting github repositories for '%s'" % github_user)
        gh = github.Github(github_token)
        user = gh.get_user()
        repositories = []
        for repo in user.get_repos(visibility = 'all'):
            if repo.owner.login != github_user:
                continue
            if exclude_forks and repo.fork:
                continue
            if exclude_private and repo.private:
                continue
            if len(include_repos) > 0 and repo.name not in include_repos:
                continue
            if len(exclude_repos) > 0 and repo.name in exclude_repos:
                continue
            repositories.append(repo)
        return repositories
    except (github.GithubException, OSError) as e:
        if exit_on_failure:
            logger.log_error("Unable to get github repositories for '%s'" % github_user)
            logger.log_error(e, quit_program = True)
        return []

# Clone a GitHub repo over HTTPS, embedding the token in the URL when one is given
def download_github_repository(
    github_user,
    github_repo,
    github_token = None,
    github_branch = None,
    output_dir = "",
    recursive = True,
    clean = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    github_url = "https://github.com/%s/%s.git" % (github_user, github_repo)
    if github_token and isinstance(github_token, str) and len(github_token):
        github_url = "https://%s@github.com/%s/%s.git" % (github_token, github_user, github_repo)
    return download_git_url(
        url = github_url,
        output_dir = output_dir,
        branch = github_branch,
        recursive = recursive,
        clean = clean,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Log whether a merge-upstream response reports an update or an already current branch
def log_github_update_response(github_user, github_repo, update_response):
    if "message" not in update_response:
        return
    update_message = update_response["message"]
    if "success" in update_message.lower():
        logger.log_info("Repository '%s' - '%s' was successfully updated from upstream" % (github_user, github_repo))
    if "branch is not behind" in update_message.lower():
        logger.log_info("Repository '%s' - '%s' was already up to date with upstream" % (github_user, github_repo))

# Sync a fork branch with its upstream through the GitHub merge-upstream API; False when the call fails
def update_github_repository(
    github_user,
    github_repo,
    github_branch,
    github_token = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # A pretend run must not merge anything
    if pretend_run:
        logger.log_info("Would update repository '%s' - '%s' from upstream" % (github_user, github_repo))
        return True

    # Get update url
    update_url = "https://api.github.com/repos/%s/%s/merge-upstream" % (github_user, github_repo)

    # Post update json
    update_response = post_remote_json(
        url = update_url,
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer %s" % github_token,
            "X-GitHub-Api-Version": "2022-11-28"
        },
        data = {
            "branch": github_branch
        },
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not update_response:
        return False

    # Print response
    log_github_update_response(github_user, github_repo, update_response)

    # Should be successful
    return True

# Clone a GitHub repo, zip it with a timestamped name and back the zip up to the locker
def archive_github_repository(
    github_user,
    github_repo,
    github_token = None,
    github_branch = None,
    output_dir = "",
    recursive = True,
    clean = False,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Archive through a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
        if not tmp_dir_result:
            return False
        return archive_github_repository_via(
            tmp_dir = tmp_dir_result,
            github_user = github_user,
            github_repo = github_repo,
            github_token = github_token,
            github_branch = github_branch,
            output_dir = output_dir,
            recursive = recursive,
            clean = clean,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Make the download and archive staging directories
def make_github_archive_dirs(tmp_dir_download, tmp_dir_archive, verbose = False, pretend_run = False, exit_on_failure = False):
    fileops.make_directory(
        src = tmp_dir_download,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    fileops.make_directory(
        src = tmp_dir_archive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Back the archive up to out_file_archive's locker path, skipping an existing or identical copy; False with an error on failure
def backup_github_repository_archive(
    tmp_file_archive,
    out_file_archive,
    locker_type,
    github_user,
    github_repo,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    dest_rel_path = locker.convert_to_relative_path(out_file_archive)
    success = locker.backup(
        src = tmp_file_archive,
        dest_rel_path = dest_rel_path,
        locker_type = locker_type,
        show_progress = True,
        skip_existing = True,
        skip_identical = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Backup failed for archive of repository '%s' - '%s'" % (github_user, github_repo))
        return False
    return True

# Clone the repo into the download dir, dropping its .git folder on a clean clone; False with an error when the clone fails
def download_github_repository_snapshot(
    tmp_dir_download,
    github_user,
    github_repo,
    github_token = None,
    github_branch = None,
    recursive = True,
    clean = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    success = download_github_repository(
        github_user = github_user,
        github_repo = github_repo,
        github_token = github_token,
        github_branch = github_branch,
        output_dir = tmp_dir_download,
        recursive = recursive,
        clean = clean,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download repository '%s' - '%s'" % (github_user, github_repo))
        return False
    if not clean:
        return True
    return fileops.remove_directory(
        src = paths.join_paths(tmp_dir_download, ".git"),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Zip a downloaded repository and test the zip, logging which step failed; a pretend run writes no archive to look for
def zip_github_repository_download(
    tmp_file_archive,
    tmp_dir_download,
    github_user,
    github_repo,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    archive.create_archive_from_folder(
        archive_file = tmp_file_archive,
        source_dir = tmp_dir_download,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not pretend_run and not os.path.exists(tmp_file_archive):
        logger.log_error("Unable to archive repository '%s' - '%s'" % (github_user, github_repo))
        return False
    success = archive.test_archive(
        archive_file = tmp_file_archive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Validation failed for archive of repository '%s' - '%s'" % (github_user, github_repo))
        return False
    return True

# Archive github repository via a temporary directory
def archive_github_repository_via(
    tmp_dir,
    github_user,
    github_repo,
    github_token = None,
    github_branch = None,
    output_dir = "",
    recursive = True,
    clean = False,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make temporary dirs
    tmp_dir_download = paths.join_paths(tmp_dir, "download")
    tmp_dir_archive = paths.join_paths(tmp_dir, "archive")
    tmp_file_archive = paths.join_paths(tmp_dir_archive, "tmp.zip")
    out_file_archive = paths.join_paths(output_dir, github_repo + "_" + str(runtime.get_current_timestamp()) + config.ArchiveFileType.ZIP.cval())
    make_github_archive_dirs(tmp_dir_download, tmp_dir_archive, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Download repository
    success = download_github_repository_snapshot(
        tmp_dir_download, github_user, github_repo,
        github_token = github_token, github_branch = github_branch, recursive = recursive, clean = clean,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Archive repository
    success = zip_github_repository_download(
        tmp_file_archive, tmp_dir_download, github_user, github_repo,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Backup archive
    return backup_github_repository_archive(
        tmp_file_archive, out_file_archive, locker_type, github_user, github_repo,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
