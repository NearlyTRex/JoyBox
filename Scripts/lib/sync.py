# Imports
import os
import os.path
import sys
import re
import datetime

# Local imports
import config
import command
import programs
import serialization
import system
import logger
import paths
import environment
import fileops

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
        return None

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
        return None

    # Extract timestamp from lsl output
    match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', lsl_text)
    if match:
        try:
            dt = datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except:
            return None
    return None

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

# Check if path exists
def does_path_exist(
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
    copy_cmd = [
        rclone_tool,
        "copy",
        get_remote_connection_path(remote_name, remote_type, remote_path),
        local_path
    ]
    copy_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.DOWNLOAD)
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
    return code == 0

# Upload files to remote
def upload_files_to_remote(
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
    return code == 0

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
        diff_dir = fileops.create_temporary_directory()
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
            if local_mtime is None or remote_mtime is None:
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
