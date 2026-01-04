# Imports
import os
import os.path
import sys
import re
import concurrent.futures

# Local imports
import config
import command
import programs
import serialization
import strings
import system
import logger
import paths
import environment
import fileops
import hashing

# Constants
HASH_SIDECAR_FOLDER = ".locker_hashes"

# Check if tool is installed
def is_tool_installed():
    return programs.is_tool_installed("RClone")

# Get unencrypted remote name
def get_unencrypted_remote_name(remote_name):
    if remote_name.endswith("Enc"):
        return remote_name[:-len("Enc")]
    return remote_name

# Get encrypted remote name
def get_encrypted_remote_name(remote_name):
    if remote_name.endswith("Enc"):
        return remote_name
    return "%sEnc" % (remote_name)

# Get remote raw type
def get_remote_raw_type(remote_type):
    return config.RemoteType.to_lower_string(remote_type)

# Get remote connection path
def get_remote_connection_path(remote_name, remote_type, remote_path):
    if remote_type == config.RemoteType.B2:
        return "%s:%s%s" % (remote_name, get_unencrypted_remote_name(remote_name), remote_path)
    else:
        return "%s:%s" % (remote_name, remote_path)

# Get common remote flags
def get_common_remote_flags(remote_name, remote_type, remote_action_type):
    flags = [
        "--fast-list",
        "--tpslimit", "10",
        "--transfers", "1",
        "--order-by", "size,ascending"
    ]
    if remote_action_type in config.RemoteActionSyncType.members():
        flags += [
            "--track-renames"
        ]
    if remote_action_type in config.RemoteActionChangeType.members():
        flags += [
            "--create-empty-src-dirs"
        ]
    if remote_type == config.RemoteType.DRIVE:
        flags += [
            "--drive-acknowledge-abuse",
            "--drive-stop-on-upload-limit",
            "--drive-stop-on-download-limit",
            "--drive-chunk-size", "256M"
        ]
    return flags

# Get exclude flags
def get_exclude_flags(excludes):
    flags = []
    if isinstance(excludes, list):
        for exclude in excludes:
            if len(exclude) > 0:
                flags += ["--exclude", exclude]
    elif isinstance(excludes, str) and len(excludes) > 0:
        flags += ["--exclude", excludes]
    return flags

# Get configured remotes
def get_configured_remotes(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return []

    # Get list command
    list_cmd = [
        rclone_tool,
        "listremotes"
    ]

    # Run list command
    list_output = command.run_output_command(
        cmd = list_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return remote list
    list_text = list_output
    if isinstance(list_output, bytes):
        list_text = list_output.decode()
    return list_text.splitlines()

# Check if remote is configured
def is_remote_configured(
    remote_name,
    remote_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if the remote name exists in the list of remotes
    logger.log_info("Checking if remote '%s' exists..." % remote_name)
    configured_remotes = get_configured_remotes()
    logger.log_info("Found %d configured remotes" % len(configured_remotes))
    if not any(remote.startswith(remote_name) for remote in configured_remotes):
        logger.log_info("Remote '%s' not in configured remotes" % remote_name)
        return False

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get show command
    show_cmd = [
        rclone_tool,
        "config",
        "show", remote_name
    ]

    # Run show command
    show_output = command.run_output_command(
        cmd = show_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check if the remote is configured
    show_text = show_output
    if isinstance(show_output, bytes):
        show_text = show_output.decode()
    if "couldn't find type of fs for" in show_text:
        logger.log_info("Remote type not found")
        return False

    # Check if the remote type matches
    match = re.search(r"type\s*=\s*(\S+)", show_text)
    result = match and (match.group(1) == get_remote_raw_type(remote_type))
    logger.log_info("Remote type match result: %s" % result)
    return result

# Setup autoconnect remote
def setup_autoconnect_remote(
    remote_name,
    remote_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get create command
    create_cmd = [
        rclone_tool,
        "config",
        "create", remote_name,
        get_remote_raw_type(remote_type),
        "config_is_local=false"
    ]
    if verbose:
        create_cmd += ["--verbose"]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Get authorize command
    authorize_cmd = [
        rclone_tool,
        "config",
        "reconnect", "%s:" % remote_name
    ]
    if verbose:
        authorize_cmd += ["--verbose"]

    # Run authorize command
    code = command.run_returncode_command(
        cmd = authorize_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Setup manual remote
def setup_manual_remote(
    remote_name,
    remote_type,
    remote_token = None,
    remote_config = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get create command
    create_cmd = [
        rclone_tool,
        "config",
        "create", remote_name,
        get_remote_raw_type(remote_type)
    ]
    if isinstance(remote_config, dict):
        for config_key, config_value in remote_config.items():
            create_cmd += ["%s=%s" % (config_key, config_value)]
    if verbose:
        create_cmd += ["--verbose"]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Setup encrypted remote
def setup_encrypted_remote(
    remote_name,
    remote_path,
    remote_encryption_key,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get create command
    create_cmd = [
        rclone_tool,
        "config",
        "create", get_encrypted_remote_name(remote_name),
        "crypt",
        "remote=%s:" % remote_name,
        "password=%s" % remote_encryption_key
    ]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Setup remote
def setup_remote(
    remote_name,
    remote_type,
    remote_token = None,
    remote_config = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Drive can use automatic setting
    if remote_type == config.RemoteType.DRIVE:
        return setup_autoconnect_remote(
            remote_type = remote_type,
            remote_name = remote_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Others should use manual
    else:
        if isinstance(remote_config, str):
            remote_config = serialization.parse_json_string(remote_config)
        return setup_manual_remote(
            remote_type = remote_type,
            remote_name = remote_name,
            remote_token = remote_token,
            remote_config = remote_config,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Get path MD5
def get_path_md5(
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

    # Get md5sum command
    md5sum_cmd = [
        rclone_tool,
        "md5sum",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run md5sum command
    md5sum_output = command.run_output_command(
        cmd = md5sum_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get md5
    md5sum_text = md5sum_output
    if isinstance(md5sum_output, bytes):
        md5sum_text = md5sum_output.decode()
    if "file does not exist" in md5sum_text or "error" in md5sum_text:
        return None
    md5sum_parts = md5sum_text.strip().split("  ", 1)
    if len(md5sum_parts) > 1:
        return md5sum_parts[0]
    return None

# Get path modification time as timestamp
def get_path_mod_time(
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
        return 0

    # Get lsl command (outputs: size modtime filename)
    lsl_cmd = [
        rclone_tool,
        "lsl",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run lsl command
    lsl_output = command.run_output_command(
        cmd = lsl_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Parse output (format: "  size YYYY-MM-DD HH:MM:SS.nnnnnnnnn filename")
    lsl_text = lsl_output
    if isinstance(lsl_output, bytes):
        lsl_text = lsl_output.decode()
    if "error" in lsl_text.lower() or "not found" in lsl_text.lower():
        return 0

    # Extract timestamp from lsl output
    match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', lsl_text)
    if match:
        return strings.parse_timestamp(match.group(1))
    return 0

# Check if path matches md5
def does_path_match_md5(
    remote_name,
    remote_type,
    remote_path,
    expected_md5,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get MD5 checksum from remote path
    remote_md5 = GetFileMD5Sum(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check match
    if remote_md5 and remote_md5.lower() == expected_md5.lower():
        return True
    return False

# Check if directory exists on remote
def does_directory_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get list command
    list_cmd = [
        rclone_tool,
        "lsf",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run list command
    list_output = command.run_output_command(
        cmd = list_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check existence
    list_text = list_output
    if isinstance(list_output, bytes):
        list_text = list_output.decode()
    if "ERROR" in list_text:
        return False
    elif "error listing" in list_text:
        return False
    elif "directory not found" in list_text:
        return False
    return True

# Check if file exists on remote
def does_file_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Use rclone lsjson to check if specific file exists
    lsjson_cmd = [
        rclone_tool,
        "lsjson",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run lsjson command - returns 0 if file exists, non-zero if not
    options = command.create_command_options()
    options.set_suppress_output(True)
    code = command.run_returncode_command(
        cmd = lsjson_cmd,
        options = options,
        verbose = verbose)
    return code == 0

# Check if path (file or directory) exists on remote
def does_path_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if file exists
    if does_file_exist(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        verbose = verbose):
        return True

    # Check if directory exists
    return does_directory_exist(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Check if path contains files
def does_path_contain_files(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get list command
    list_cmd = [
        rclone_tool,
        "lsf",
        "--files-only",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run list command
    list_output = command.run_output_command(
        cmd = list_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check if there are any files in the directory
    list_text = list_output
    if isinstance(list_output, bytes):
        list_text = list_output.decode()
    return len(list_text.strip()) > 0

# Create directory on remote
def create_remote_directory(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        return False

    # Build mkdir command
    mkdir_cmd = [
        rclone_tool,
        "mkdir",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    if verbose:
        mkdir_cmd += ["--verbose"]

    # Run command
    code = command.run_returncode_command(
        cmd = mkdir_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)
    if code == 0:
        return True

    # Check if failure was due to directory already existing
    output = command.run_output_command(
        cmd = mkdir_cmd,
        options = command.create_command_options(include_stderr = True),
        verbose = False,
        pretend_run = pretend_run,
        exit_on_failure = False)
    if "already exist" in output.lower():
        return True
    return False

# Download files from remote
def download_files_from_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    files_from = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get copy command
    is_directory_dest = local_path.endswith("/") or paths.is_path_directory(local_path)
    copy_cmd = [
        rclone_tool,
        "copy" if is_directory_dest else "copyto",
        get_remote_connection_path(remote_name, remote_type, remote_path),
        local_path
    ]
    if is_directory_dest:
        copy_cmd += get_common_remote_flags(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_action_type = config.RemoteActionType.DOWNLOAD)
        copy_cmd += get_exclude_flags(excludes)
        if files_from and paths.is_path_file(files_from):
            copy_cmd += ["--files-from", files_from]
        if interactive:
            copy_cmd += ["--interactive"]
    if pretend_run:
        copy_cmd += ["--dry-run"]
    if verbose:
        copy_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run copy command
    code = command.run_returncode_command(
        cmd = copy_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Upload files to remote
def upload_files_to_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    local_root = None,
    excludes = None,
    files_from = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get copy command
    copy_cmd = [
        rclone_tool,
        "copy",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    copy_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.UPLOAD)
    copy_cmd += get_exclude_flags(excludes)
    if files_from and paths.is_path_file(files_from):
        copy_cmd += ["--files-from", files_from]
    if pretend_run:
        copy_cmd += ["--dry-run"]
    if interactive:
        copy_cmd += ["--interactive"]
    if verbose:
        copy_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run copy command
    code = command.run_returncode_command(
        cmd = copy_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Upload hash sidecars to local root if specified
    if local_root is not None:
        upload_hash_sidecar_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            local_root = local_root,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
    return True

# Move files on remote
def move_files_on_remote(
    remote_name,
    remote_type,
    src_path,
    dest_path,
    files_from = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Build full remote paths
    src_full = get_remote_connection_path(remote_name, remote_type, src_path)
    dest_full = get_remote_connection_path(remote_name, remote_type, dest_path)

    # Build move command
    move_cmd = [
        rclone_tool,
        "move",
        src_full,
        dest_full
    ]
    if files_from and paths.is_path_file(files_from):
        move_cmd += ["--files-from", files_from]
    if pretend_run:
        move_cmd += ["--dry-run"]
    if verbose:
        move_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run move command
    code = command.run_returncode_command(
        cmd = move_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Purge path on remote
def purge_path_on_remote(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Build full remote path
    remote_full = get_remote_connection_path(remote_name, remote_type, remote_path)

    # Build purge command
    purge_cmd = [
        rclone_tool,
        "purge",
        remote_full
    ]
    if pretend_run:
        purge_cmd += ["--dry-run"]
    if verbose:
        purge_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run purge command
    code = command.run_returncode_command(
        cmd = purge_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Move files to recycle bin on remote
def recycle_files_on_remote(
    remote_name,
    remote_type,
    remote_path,
    files_from,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get recycle bin path on remote
    recycle_bin_path = os.path.join(remote_path, recycle_folder).replace("\\", "/")

    # Move files to recycle bin
    return move_files_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        src_path = remote_path,
        dest_path = recycle_bin_path,
        files_from = files_from,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Empty recycle bin on remote
def empty_recycle_bin(
    remote_name,
    remote_type,
    remote_path,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get recycle bin path on remote
    recycle_bin_path = os.path.join(remote_path, recycle_folder).replace("\\", "/")

    # Purge recycle bin
    return purge_path_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = recycle_bin_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Pull files from remote
def pull_files_from_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        get_remote_connection_path(remote_name, remote_type, remote_path),
        local_path
    ]
    sync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PULL)
    sync_cmd += get_exclude_flags(excludes)
    if pretend_run:
        sync_cmd += ["--dry-run"]
    if interactive:
        sync_cmd += ["--interactive"]
    if verbose:
        sync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run sync command
    code = command.run_returncode_command(
        cmd = sync_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Push files to remote
def push_files_to_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    sync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PUSH)
    sync_cmd += get_exclude_flags(excludes)
    if pretend_run:
        sync_cmd += ["--dry-run"]
    if interactive:
        sync_cmd += ["--interactive"]
    if verbose:
        sync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run sync command
    code = command.run_returncode_command(
        cmd = sync_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Merge files both ways
def merge_files_both_ways(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    resync = False,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get bisync command
    bisync_cmd = [
        rclone_tool,
        "bisync",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path),
        "--check-access"
    ]
    bisync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.MERGE)
    bisync_cmd += get_exclude_flags(excludes)
    if resync:
        bisync_cmd += ["--resync"]
    if pretend_run:
        bisync_cmd += ["--dry-run"]
    if interactive:
        bisync_cmd += ["--interactive"]
    if verbose:
        bisync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run bisync command
    code = command.run_returncode_command(
        cmd = bisync_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Diff files
def diff_files(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    diff_combined_path = None,
    diff_intersected_path = None,
    diff_missing_src_path = None,
    diff_missing_dest_path = None,
    diff_error_path = None,
    quick = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Exclude hidden files/folders (starting with .) from diff operations
    dotfile_exclude = ".*/**"
    if excludes is None:
        excludes = [dotfile_exclude]
    elif isinstance(excludes, list):
        if dotfile_exclude not in excludes:
            excludes = excludes + [dotfile_exclude]
    elif isinstance(excludes, str):
        excludes = [excludes, dotfile_exclude]

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get check command
    check_cmd = [
        rclone_tool,
        "check",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    check_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.DIFF)
    check_cmd += get_exclude_flags(excludes)
    if paths.is_path_valid(diff_combined_path):
        check_cmd += ["--combined", diff_combined_path]
    if paths.is_path_valid(diff_intersected_path):
        check_cmd += ["--differ", diff_intersected_path]
    if paths.is_path_valid(diff_missing_src_path):
        check_cmd += ["--missing-on-src", diff_missing_src_path]
    if paths.is_path_valid(diff_missing_dest_path):
        check_cmd += ["--missing-on-dst", diff_missing_dest_path]
    if paths.is_path_valid(diff_error_path):
        check_cmd += ["--error", diff_error_path]
    if quick:
        check_cmd += ["--size-only"]
    if verbose:
        check_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run check command
    command.run_returncode_command(
        cmd = check_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Analyze combined output
    if os.path.exists(diff_combined_path):
        count_unchanged = 0
        count_changed = 0
        count_only_dest = 0
        count_only_src = 0
        count_error = 0
        with open(diff_combined_path, "r", encoding="utf8") as f:
            for line in f.readlines():
                if line.startswith("="):
                    count_unchanged += 1
                elif line.startswith("-"):
                    count_only_dest += 1
                elif line.startswith("+"):
                    count_only_src += 1
                elif line.startswith("*"):
                    count_changed += 1
                elif line.startswith("!"):
                    count_error += 1
        logger.log_info("Number of unchanged files: %d" % count_unchanged)
        logger.log_info("Number of changed files: %d" % count_changed)
        logger.log_info("Number of files only on %s%s: %d" % (get_remote_raw_type(remote_type), remote_path, count_only_dest))
        logger.log_info("Number of files only on %s: %d" % (local_path, count_only_src))
        logger.log_info("Number of error files: %d" % count_error)

    # Sort diff files
    for diff_path in [diff_combined_path, diff_intersected_path, diff_missing_src_path, diff_missing_dest_path, diff_error_path]:
        if diff_path and os.path.exists(diff_path):
            fileops.sort_file_contents(
                src = diff_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Diff sync files
def diff_sync_files(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    diff_dir = None,
    diff_combined_file = "diff_combined.txt",
    diff_intersected_file = "diff_intersected.txt",
    diff_missing_src_file = "diff_missing_src.txt",
    diff_missing_dest_file = "diff_missing_dest.txt",
    sync_changed = True,
    recycle_missing = False,
    recycle_folder = ".recycle_bin",
    quick = False,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Determine if generating diffs
    generate_diffs = diff_dir is None

    # Get diff directory
    if not diff_dir:
        success, diff_dir = fileops.create_temporary_directory()
        if not success:
            logger.log_error("Failed to create diff directory")
            return False
    if not paths.does_path_exist(diff_dir):
        logger.log_error("Diff directory was invalid")
        return False

    # Exclude hidden files/folders (starting with .) from diff operations
    dotfile_exclude = ".*/**"
    if excludes is None:
        excludes = [dotfile_exclude]
    elif isinstance(excludes, list):
        if dotfile_exclude not in excludes:
            excludes = excludes + [dotfile_exclude]
    elif isinstance(excludes, str):
        excludes = [excludes, dotfile_exclude]

    # Exclude recycle folder from diff operations
    if recycle_folder:
        recycle_bin_exclude = recycle_folder + "/**"
        if recycle_bin_exclude not in excludes:
            excludes = excludes + [recycle_bin_exclude]

    # Setup diff file paths
    diff_combined_path = os.path.join(diff_dir, diff_combined_file)
    diff_intersected_path = os.path.join(diff_dir, diff_intersected_file)
    diff_missing_src_path = os.path.join(diff_dir, diff_missing_src_file)
    diff_missing_dest_path = os.path.join(diff_dir, diff_missing_dest_file)

    # Diff files if necessary
    if generate_diffs:
        logger.log_info("Running diff to identify file differences...")
        diff_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            diff_combined_path = diff_combined_path,
            diff_intersected_path = diff_intersected_path,
            diff_missing_src_path = diff_missing_src_path,
            diff_missing_dest_path = diff_missing_dest_path,
            quick = quick,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read files missing on dest (need to upload from local)
    files_to_upload = []
    if os.path.exists(diff_missing_dest_path):
        with open(diff_missing_dest_path, "r", encoding="utf8") as f:
            files_to_upload = [line.strip() for line in f.readlines() if line.strip()]

    # Read files missing on src (need to download from remote)
    files_to_download = []
    if os.path.exists(diff_missing_src_path):
        with open(diff_missing_src_path, "r", encoding="utf8") as f:
            files_to_download = [line.strip() for line in f.readlines() if line.strip()]

    # Read changed files (exist on both but differ)
    changed_files = []
    if sync_changed and os.path.exists(diff_intersected_path):
        with open(diff_intersected_path, "r", encoding="utf8") as f:
            changed_files = [line.strip() for line in f.readlines() if line.strip()]

    # Log file change
    logger.log_info("Files to upload (missing on remote): %d" % len(files_to_upload))
    logger.log_info("Files to download (missing on local): %d" % len(files_to_download))
    logger.log_info("Files changed (differ on both): %d" % len(changed_files))

    # Handle changed files by comparing modification times
    if changed_files:
        logger.log_info("Comparing modification times for changed files...")
        changed_to_upload = []
        changed_to_download = []
        for file_path in changed_files:
            local_file = os.path.join(local_path, file_path)
            remote_file_path = os.path.join(remote_path, file_path).replace("\\", "/")

            # Get local modtime
            local_mtime = paths.get_file_mod_time(local_file)

            # Get remote modtime
            remote_mtime = get_path_mod_time(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_file_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not local_mtime or not remote_mtime:
                if verbose:
                    logger.log_warning("Could not get modtime for: %s" % file_path)
                continue

            # Add to changes lists
            if local_mtime > remote_mtime:
                if verbose:
                    logger.log_info("Local is newer: %s" % file_path)
                changed_to_upload.append(file_path)
            elif remote_mtime > local_mtime:
                if verbose:
                    logger.log_info("Remote is newer: %s" % file_path)
                changed_to_download.append(file_path)

        # Add changed files to upload/download lists
        logger.log_info("Changed files to upload (local newer): %d" % len(changed_to_upload))
        logger.log_info("Changed files to download (remote newer): %d" % len(changed_to_download))
        files_to_upload.extend(changed_to_upload)
        files_to_download.extend(changed_to_download)

    # Upload files
    if files_to_upload:
        final_upload_path = fileops.create_temporary_file(suffix = ".txt")
        serialization.write_text_file(final_upload_path, "\n".join(files_to_upload))
        logger.log_info("Uploading %d files to remote..." % len(files_to_upload))
        if not upload_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            files_from = final_upload_path,
            interactive = interactive,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            return False

    # Download or recycle files
    if files_to_download:
        if recycle_missing:
            final_recycle_path = fileops.create_temporary_file(suffix = ".txt")
            serialization.write_text_file(final_recycle_path, "\n".join(files_to_download))
            logger.log_info("Recycling %d files on remote (moving to %s)..." % (len(files_to_download), recycle_folder))
            if not recycle_files_on_remote(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_path,
                files_from = final_recycle_path,
                recycle_folder = recycle_folder,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False
        else:
            final_download_path = fileops.create_temporary_file(suffix = ".txt")
            serialization.write_text_file(final_download_path, "\n".join(files_to_download))
            logger.log_info("Downloading %d files from remote..." % len(files_to_download))
            if not download_files_from_remote(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_path,
                local_path = local_path,
                files_from = final_download_path,
                interactive = interactive,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False

    # Done
    logger.log_info("DiffSync complete!")
    return True

# List files
def list_files(
    remote_name,
    remote_type,
    remote_path,
    recursive = False,
    only_directories = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get list command
    list_cmd = [rclone_tool]
    if only_directories:
        if recursive:
            list_cmd += ["lsd", "-R"]
        else:
            list_cmd += ["lsd"]
    else:
        if recursive:
            list_cmd += ["ls"]
        else:
            list_cmd += ["ls", "--max-depth", 1]
    list_cmd += [
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run list command
    code = command.run_returncode_command(
        cmd = list_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Mount files
def mount_files(
    remote_name,
    remote_type,
    remote_path,
    mount_path,
    no_cache = False,
    no_checksum = False,
    no_modtime = False,
    no_seek = False,
    read_only = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Ignore already mounted
    if paths.does_path_exist(mount_path) and not paths.is_directory_empty(mount_path):
        return True

    # Create mount point
    if environment.is_unix_platform():
        fileops.make_directory(
            src = mount_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not paths.does_path_exist(mount_path) or not paths.is_directory_empty(mount_path):
            logger.log_error("Mount point %s needs to exist and be empty" % mount_path)
            return False

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get mount command
    mount_cmd = [
        rclone_tool,
        "mount"
    ]
    if no_cache:
        mount_cmd += [
            "--vfs-cache-mode", "off"
        ]
    else:
        mount_cmd += [
            "--vfs-cache-mode", "full"
        ]
    mount_cmd += [
        get_remote_connection_path(remote_name, remote_type, remote_path),
        mount_path
    ]
    if environment.is_unix_platform():
        mount_cmd += ["--daemon"]
    if no_checksum:
        mount_cmd += ["--no-checksum"]
    if no_modtime:
        mount_cmd += ["--no-modtime"]
    if no_seek:
        mount_cmd += ["--no-seek"]
    if read_only:
        mount_cmd += ["--read-only"]
    if verbose:
        mount_cmd += [
            "--log-file", "/tmp/rclone.log",
            "--log-level", "INFO"
        ]

    # Run mount command
    code = command.run_returncode_command(
        cmd = mount_cmd,
        options = command.create_command_options(
            is_daemon = environment.is_unix_platform()),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Copy file from one remote to another
def copy_remote_to_remote(
    src_remote_name,
    src_remote_type,
    src_remote_path,
    dest_remote_name,
    dest_remote_type,
    dest_remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Build source and dest paths
    src_full = get_remote_connection_path(src_remote_name, src_remote_type, src_remote_path)
    dest_full = get_remote_connection_path(dest_remote_name, dest_remote_type, dest_remote_path)

    # Build copyto command
    copyto_cmd = [
        rclone_tool,
        "copyto",
        src_full,
        dest_full
    ]
    if pretend_run:
        copyto_cmd += ["--dry-run"]
    if verbose:
        copyto_cmd += ["--verbose", "--progress"]

    # Run copyto command
    code = command.run_returncode_command(
        cmd = copyto_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# List files with hashes
def list_files_with_hashes(
    remote_name,
    remote_type,
    remote_path,
    hash_type = None,
    excludes = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Use default hash type
    if hash_type is None:
        hash_type = config.HashType.MD5

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return {}

    # Build lsjson command
    lsjson_cmd = [
        rclone_tool,
        "lsjson",
        "--recursive",
        "--hash",
        "--files-only",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Add exclude flags
    lsjson_cmd += get_exclude_flags(excludes)
    if verbose:
        logger.log_info("Listing files with hashes from remote: %s" % remote_name)

    # Run lsjson command
    lsjson_output = command.run_output_command(
        cmd = lsjson_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Parse JSON output
    hash_map = {}
    lsjson_text = lsjson_output
    if isinstance(lsjson_output, bytes):
        lsjson_text = lsjson_output.decode()
    if not lsjson_text or lsjson_text.strip() == "":
        return hash_map
    files_list = serialization.parse_json_string(lsjson_text)
    if not files_list:
        return hash_map

    # Build map
    for file_info in files_list:
        if file_info.get("IsDir", False):
            continue
        rel_path = file_info.get("Path", "")
        if not rel_path:
            continue

        # Get hash from Hashes dict
        hashes = file_info.get("Hashes", {})
        file_hash = ""
        if hash_type == config.HashType.MD5:
            file_hash = hashes.get("MD5", hashes.get("md5", ""))
        elif hash_type == config.HashType.SHA1:
            file_hash = hashes.get("SHA-1", hashes.get("sha1", ""))
        elif hash_type == config.HashType.SHA256:
            file_hash = hashes.get("SHA-256", hashes.get("sha256", ""))

        # Parse modification time
        mtime = strings.parse_timestamp(file_info.get("ModTime", ""))

        # Add to map
        hash_map[rel_path] = {
            "filename": paths.get_filename_file(rel_path),
            "dir": paths.get_filename_directory(rel_path),
            "hash": file_hash,
            "size": file_info.get("Size", 0),
            "mtime": mtime
        }

    # All done
    if verbose:
        logger.log_info("Loaded %d file hashes" % len(hash_map))
    return hash_map

# List files with hashes from sidecar files
def list_files_with_hashes_from_sidecar(
    remote_name,
    remote_type,
    remote_path,
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

    # Build sidecar folder path
    sidecar_path = get_hash_sidecar_folder_path(remote_path)
    sidecar_connection = get_remote_connection_path(remote_name, remote_type, sidecar_path)

    # List all .json files in sidecar folder
    lsjson_cmd = [
        rclone_tool,
        "lsjson",
        "--recursive",
        "--files-only",
        sidecar_connection
    ]
    if verbose:
        logger.log_info("Listing hash sidecar files from: %s" % sidecar_path)

    # Run lsjson command
    lsjson_output = command.run_output_command(
        cmd = lsjson_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)  # Don't fail if folder doesn't exist

    # Parse JSON output
    lsjson_text = lsjson_output
    if isinstance(lsjson_output, bytes):
        lsjson_text = lsjson_output.decode()
    if not lsjson_text or lsjson_text.strip() == "" or "error" in lsjson_text.lower():
        if verbose:
            logger.log_info("No hash sidecar files found")
        return {}

    # Parse file list
    files_list = serialization.parse_json_string(lsjson_text)
    if not files_list:
        return {}

    # Filter to only .json files
    hash_files = [f for f in files_list if f.get("Path", "").endswith(".json") and not f.get("IsDir", False)]
    if not hash_files:
        if verbose:
            logger.log_info("No .json files found in sidecar folder")
        return {}
    if verbose:
        logger.log_info("Found %d hash sidecar files" % len(hash_files))

    # Create temp directory for downloads
    success, temp_dir = fileops.create_temporary_directory()
    if not success:
        logger.log_error("Failed to create temp directory")
        return {}
    hash_map = {}

    # Build hash map
    try:
        # Download and parse each hash file
        for hash_file_info in hash_files:
            hash_file_path = hash_file_info.get("Path", "")
            if not hash_file_path:
                continue

            # Download hash file to temp
            remote_hash_path = paths.join_paths(sidecar_path, hash_file_path).replace("\\", "/")
            temp_hash_file = paths.join_paths(temp_dir, paths.get_filename_file(hash_file_path))
            success = download_files_from_remote(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_hash_path,
                local_path = temp_hash_file,
                verbose = False,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not success:
                continue

            # Parse hash file
            hash_data = serialization.read_json_file(src = temp_hash_file)
            if not hash_data:
                continue

            # Add each entry to the hash map
            base_path = hash_file_path[:-5]
            for rel_file, file_data in hash_data.items():
                full_rel_path = paths.join_paths(base_path, rel_file).replace("\\", "/")
                hash_map[full_rel_path] = {
                    "filename": paths.get_filename_file(rel_file),
                    "dir": paths.get_filename_directory(full_rel_path),
                    "hash": file_data.get("hash", ""),
                    "size": file_data.get("size", 0),
                    "mtime": file_data.get("mtime", 0)
                }

            # Clean up temp hash file
            fileops.remove_file(temp_hash_file)

    finally:

        # Clean up temp dir
        fileops.remove_directory(temp_dir)

    # All done
    if verbose:
        logger.log_info("Loaded %d file hashes from sidecar files" % len(hash_map))
    return hash_map

# Get hash sidecar folder path
def get_hash_sidecar_folder_path(remote_path = "", rel_path = ""):
    sidecar_path = paths.join_paths(remote_path, HASH_SIDECAR_FOLDER)
    if rel_path:
        sidecar_path = paths.join_paths(sidecar_path, rel_path)
    return sidecar_path.replace("\\", "/")

# Get hash sidecar relative path
def get_hash_sidecar_relative_path(local_root, remote_path):
    if local_root and remote_path.startswith(local_root):
        rel_path = remote_path[len(local_root):].lstrip("/")
    else:
        rel_path = remote_path.lstrip("/")
    return (rel_path + ".json") if rel_path else "root.json"

# Check if hash sidecar exists on remote
def does_hash_sidecar_exist(
    remote_name,
    remote_type,
    local_root,
    sidecar_rel,
    verbose = False):

    # Build remote sidecar path
    sidecar_remote = get_hash_sidecar_folder_path(local_root, sidecar_rel)

    # Use general file exist check
    return does_file_exist(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = sidecar_remote,
        verbose = verbose)

# Check if hash sidecar data is valid
def is_hash_sidecar_data_valid(sidecar_data):

    # Check if we got valid data (non-empty dict)
    if not sidecar_data or not isinstance(sidecar_data, dict):
        return False

    # Validate structure - should have file paths as keys with hash info dicts as values
    for key, value in sidecar_data.items():
        if not isinstance(key, str):
            return False
        if not isinstance(value, dict):
            return False
        if "hash" not in value or not isinstance(value.get("hash"), str):
            return False
    return True

# Build hash sidecar data
def build_hash_sidecar_data(local_path, pretend_run = False, verbose = False):
    hash_data = {}

    # Process files to add
    if paths.is_path_file(local_path):

        # Single file
        filename = paths.get_filename_file(local_path)
        file_hash = hashing.calculate_file_md5(src = local_path, verbose = False, pretend_run = pretend_run)
        if file_hash:
            hash_data[filename] = {
                "hash": file_hash,
                "size": paths.get_file_size(local_path),
                "mtime": paths.get_file_mod_time(local_path)
            }
    elif paths.is_path_directory(local_path):

        # Build file list
        file_list = [f for f in paths.build_file_list(local_path, use_relative_paths = True)]
        total_files = len(file_list)
        if verbose and total_files > 0:
            logger.log_info("  Hashing %d files..." % total_files)

        # Hash files in parallel using thread pool
        completed = [0]
        def hash_file(rel_file):
            full_file = paths.join_paths(local_path, rel_file)
            if not paths.is_path_file(full_file):
                return None
            file_hash = hashing.calculate_file_md5(src = full_file, verbose = False, pretend_run = pretend_run)
            if file_hash:
                return (rel_file, {
                    "hash": file_hash,
                    "size": paths.get_file_size(full_file),
                    "mtime": paths.get_file_mod_time(full_file)
                })
            return None

        # Hash files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers = 16) as executor:
            futures = {executor.submit(hash_file, rel_file): rel_file for rel_file in file_list}
            for future in concurrent.futures.as_completed(futures):
                completed[0] += 1
                if verbose and total_files > 100 and completed[0] % 100 == 0:
                    logger.log_info("  Hashed %d/%d files..." % (completed[0], total_files))
                result = future.result()
                if result:
                    hash_data[result[0]] = result[1]
    return hash_data

# Read hash sidecar data
def read_hash_sidecar_data(
    remote_name,
    remote_type,
    local_root,
    sidecar_rel,
    verbose = False,
    pretend_run = False):

    # Build remote sidecar path
    sidecar_remote = get_hash_sidecar_folder_path(local_root, sidecar_rel)

    # Create temp file for download
    temp_file = fileops.create_temporary_file(suffix = ".json")
    if not temp_file:
        return {}

    try:
        # Download sidecar
        success = download_files_from_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = sidecar_remote,
            local_path = temp_file,
            verbose = False,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not success:
            return {}

        # Parse sidecar
        return serialization.read_json_file(src = temp_file) or {}

    finally:

        # Clean up temp file
        fileops.remove_file(temp_file)

# Write hash sidecar data
def write_hash_sidecar_data(
    remote_name,
    remote_type,
    local_root,
    sidecar_rel,
    hash_data,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        return False

    # Create temp directory with sidecar
    success, temp_dir = fileops.create_temporary_directory()
    if not success:
        return False

    try:
        # Write sidecar JSON with mirrored directory structure
        temp_sidecar = paths.join_paths(temp_dir, sidecar_rel)
        fileops.make_directory(paths.get_filename_directory(temp_sidecar))
        if not serialization.write_json_file(src = temp_sidecar, json_data = hash_data, verbose = verbose):
            return False

        # Get sidecar path
        sidecar_remote = get_hash_sidecar_folder_path(local_root)
        if verbose:
            logger.log_info("Uploading sidecar to: %s:%s/%s" % (remote_name, sidecar_remote, sidecar_rel))

        # Get upload command
        copy_cmd = [
            rclone_tool,
            "copy",
            temp_dir,
            get_remote_connection_path(remote_name, remote_type, sidecar_remote)
        ]
        if pretend_run:
            copy_cmd += ["--dry-run"]
        if verbose:
            copy_cmd += ["--verbose"]

        # Run upload command
        code = command.run_returncode_command(
            cmd = copy_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    finally:

        # Clean up temp dir
        fileops.remove_directory(temp_dir)

# Clear hash sidecar files
def clear_hash_sidecar_files(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build sidecar folder path
    sidecar_path = get_hash_sidecar_folder_path(remote_path)

    # Purge the sidecar folder
    return purge_path_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = sidecar_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Upload hash sidecar files
def upload_hash_sidecar_files(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    local_root,
    skip_existing = False,
    precreate_dirs = True,
    parallel_dirs = 4,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Collect all leaf directories
    leaf_dirs = []
    work_queue = [(local_path, remote_path)]
    while work_queue:

        # Check for subdirectories
        current_local, current_remote = work_queue.pop()
        subdirs = []
        if paths.is_path_directory(current_local):
            for entry in os.listdir(current_local):
                entry_path = paths.join_paths(current_local, entry)
                if paths.is_path_directory(entry_path) and not entry.startswith("."):
                    subdirs.append(entry)

        # Add subdirectories to work queue (reverse sort so alphabetically first is processed first)
        if subdirs:
            for subdir in sorted(subdirs, reverse=True):
                subdir_local = paths.join_paths(current_local, subdir)
                subdir_remote = paths.join_paths(current_remote, subdir).replace("\\", "/")
                work_queue.append((subdir_local, subdir_remote))
        else:
            leaf_dirs.append((current_local, current_remote))

    # Process leaf directories in parallel
    if not leaf_dirs:
        return True

    # Directory thread worker
    def process_dir(dir_info):
        current_local, current_remote = dir_info
        dir_name = paths.get_filename_file(current_local)
        logger.log_info("Processing: %s" % dir_name)
        return upload_hash_sidecar_file(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = current_remote,
            local_path = current_local,
            local_root = local_root,
            skip_existing = skip_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

    # Pre-create sidecar directories to avoid race conditions
    logger.log_info("Found %d directories to process" % len(leaf_dirs))
    if precreate_dirs:
        sidecar_parent_dirs = set()
        for _, current_remote in leaf_dirs:
            sidecar_rel = get_hash_sidecar_relative_path(local_root, current_remote)
            parent_dir = paths.get_filename_directory(sidecar_rel)
            if parent_dir:
                sidecar_parent_dirs.add(parent_dir)
        if sidecar_parent_dirs:
            logger.log_info("Creating %d sidecar directories..." % len(sidecar_parent_dirs))
            sidecar_root = get_hash_sidecar_folder_path(local_root)
            def create_dir(parent_dir):
                create_remote_directory(
                    remote_name = remote_name,
                    remote_type = remote_type,
                    remote_path = paths.join_paths(sidecar_root, parent_dir).replace("\\", "/"),
                    verbose = verbose,
                    pretend_run = pretend_run)
            with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_dirs) as executor:
                list(executor.map(create_dir, sidecar_parent_dirs))

    # Process directories
    all_success = True
    with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_dirs) as executor:
        futures = {executor.submit(process_dir, dir_info): dir_info for dir_info in leaf_dirs}
        for future in concurrent.futures.as_completed(futures):
            if not future.result():
                all_success = False
                if exit_on_failure:
                    executor.shutdown(wait=False, cancel_futures=True)
                    return False
    return all_success

# Upload hash sidecar file
def upload_hash_sidecar_file(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    local_root,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get sidecar relative path
    sidecar_rel = get_hash_sidecar_relative_path(local_root, remote_path)

    # Check if sidecar already exists
    existing_data = {}
    sidecar_exists = does_hash_sidecar_exist(
        remote_name = remote_name,
        remote_type = remote_type,
        local_root = local_root,
        sidecar_rel = sidecar_rel,
        verbose = verbose)

    # If exists, read the data
    if sidecar_exists:
        existing_data = read_hash_sidecar_data(
            remote_name = remote_name,
            remote_type = remote_type,
            local_root = local_root,
            sidecar_rel = sidecar_rel,
            verbose = verbose,
            pretend_run = pretend_run)

        # If skip_existing and data is valid, skip this sidecar
        if skip_existing and is_hash_sidecar_data_valid(existing_data):
            logger.log_info("Skipping (valid sidecar exists): %s" % sidecar_rel)
            return True

    # Build hash data from local files
    new_hash_data = build_hash_sidecar_data(local_path, pretend_run, verbose)
    if not new_hash_data:
        return True

    # Merge sidecar data
    existing_data.update(new_hash_data)

    # Write merged sidecar data
    return write_hash_sidecar_data(
        remote_name = remote_name,
        remote_type = remote_type,
        local_root = local_root,
        sidecar_rel = sidecar_rel,
        hash_data = existing_data,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
