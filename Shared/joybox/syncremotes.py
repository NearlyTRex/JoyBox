# rclone remotes: which are configured, setting one up, signing in to one
# with OAuth and checking it can be listed.

# Imports
import re

# Local imports
from joybox import command
from joybox import programs
from joybox import rcloneremotes
from joybox import serialization
from joybox import logger
from joybox import sync

# Get the remotes rclone can reach, by lowercased name, with their types.
# Remotes defined by the settings are passed in, since rclone only sees those
# in the environment of a command that names them.
def get_configured_remotes(
    remote_names = (),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return {}

    # Get list command
    list_cmd = [
        rclone_tool,
        "listremotes",
        "--long"
    ]

    # Run list command
    list_text, code = sync.run_query_command(
        cmd = list_cmd,
        options = rcloneremotes.get_rclone_options(remote_names),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to list configured remotes")
        return {}

    # Each line is "name: type"; rclone lowercases a name it read from the environment
    remotes = {}
    for line in list_text.splitlines():
        name, _, remote_type = line.partition(":")
        if name.strip():
            remotes[name.strip().lower()] = remote_type.strip()
    return remotes

# Check if remote is configured
def is_remote_configured(
    remote_name,
    remote_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    logger.log_info("Checking if remote '%s' exists..." % remote_name)
    configured_remotes = get_configured_remotes(
        remote_names = [remote_name],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    logger.log_info("Found %d configured remotes" % len(configured_remotes))
    found_type = configured_remotes.get(remote_name.lower())
    if found_type is None:
        logger.log_info("Remote '%s' not in configured remotes" % remote_name)
        return False
    result = found_type == sync.get_remote_raw_type(remote_type)
    logger.log_info("Remote type match result: %s" % result)
    return result

# Setup remote. Remotes are defined by the settings and reach rclone through
# the environment, so there is nothing to create: this checks the one named
# here resolves to the type expected.
def setup_remote(
    remote_name,
    remote_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if is_remote_configured(
        remote_name = remote_name,
        remote_type = remote_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        logger.log_info("Remote '%s' is defined by the settings" % remote_name)
        return True
    logger.log_error(
        "Remote '%s' is not defined as %s; set the locker's _name, _type and _config in [UserData.Share]" % (
            remote_name, sync.get_remote_raw_type(remote_type)))
    return False

# Get the token rclone prints between its paste markers, or None
def parse_authorize_output(output):
    match = re.search(r"--->\s*(\{.*?\})\s*<---End paste", output or "", re.DOTALL)
    if not match:
        return None
    token = serialization.parse_json_string(match.group(1))
    if not token.get("refresh_token"):
        return None
    return token

# Sign in to a remote type with an OAuth client and get its token. The client
# goes in the environment, not the command line; rclone's sign-in link reaches
# the terminal on stderr while the token is captured from stdout, unlogged.
def authorize_remote(
    remote_type,
    client_id,
    client_secret,
    open_browser = True,
    verbose = False,
    pretend_run = False):

    # Get rclone tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return None

    # Get authorize command
    raw_type = sync.get_remote_raw_type(remote_type)
    authorize_cmd = [rclone_tool, "authorize", raw_type]
    if not open_browser:
        authorize_cmd += ["--auth-no-open-browser"]
    authorize_options = command.create_command_options()
    authorize_options.set_env_var("RCLONE_%s_CLIENT_ID" % raw_type.upper(), client_id)
    authorize_options.set_env_var("RCLONE_%s_CLIENT_SECRET" % raw_type.upper(), client_secret)

    # Run authorize command; it waits for the sign-in, however long that takes
    authorize_text, code = sync.run_query_command(
        cmd = authorize_cmd,
        options = authorize_options,
        verbose = verbose,
        pretend_run = pretend_run)
    if pretend_run:
        return None
    if code != 0:
        logger.log_error("rclone authorize failed")
        return None
    token = parse_authorize_output(authorize_text)
    if not token:
        logger.log_error("rclone authorize printed no token with a refresh token")
    return token

# Check a remote can be signed in to and listed, returning how many entries
# are at its top level, or None
def count_remote_entries(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get rclone tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return None

    # Get lsf command
    lsf_cmd = [
        rclone_tool,
        "lsf",
        "--max-depth", "1",
        sync.get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run lsf command
    lsf_text, code = sync.run_query_command(
        cmd = lsf_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return None
    return len([line for line in lsf_text.splitlines() if line.strip()])
