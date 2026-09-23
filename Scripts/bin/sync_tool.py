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
import joybox.sync as sync
import joybox.lockerinfo as lockerinfo
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Run an rclone operation between the local locker and a remote locker.",
    details = (
        "Every action works between the local locker's directory and the remote named by the\n"
        "`-l` locker's settings (`locker_<name>_name`, `_type`, `_remote_path` in\n"
        "`[UserData.Share]`). Files are transferred as they are: this tool does not apply\n"
        "JoyBox encryption, even for a locker marked `encrypted`.\n"
        "\n"
        "Actions:\n"
        "\n"
        "- `Init`: create the rclone remote. A Google Drive remote is created and then\n"
        "  authorised with `rclone config reconnect`; other types are created from the JSON in\n"
        "  the locker's `_config` setting.\n"
        "- `Download` / `Upload`: `rclone copy` from remote to local, or local to remote. Files\n"
        "  that differ are overwritten; nothing is deleted.\n"
        "- `Pull` / `Push`: `rclone sync` from remote to local, or local to remote. The\n"
        "  destination is made identical to the source, so files that exist only at the\n"
        "  destination are deleted.\n"
        "- `Merge`: `rclone bisync --check-access` in both directions.\n"
        "- `Diff`: `rclone check` between local and remote, writing the result lists to the\n"
        "  `--diff_*_path` files and logging a count of each kind of difference.\n"
        "- `DiffSync`: uses a diff to upload local-only files, download remote-only files (or\n"
        "  recycle them with `-r`), and copy each changed file in whichever direction has the\n"
        "  newer modification time. Without `--diff_dir` it runs a fresh diff first.\n"
        "- `EmptyRecycle`: permanently delete the remote's recycle folder.\n"
        "- `List`: list every file on the remote with its size.\n"
        "- `Mount`: mount the remote at the locker's `_mount_path` with `rclone mount`, in the\n"
        "  background on Linux. The locker's `_mount_flags` may contain `no_cache`,\n"
        "  `no_checksum`, `no_modtime`, `no_seek` and `read_only`.\n"
        "\n"
        "The locker's configured `excluded_dirs` are left out of every transfer and diff unless\n"
        "`--excludes` replaces them. `Diff` and `DiffSync` also skip dot-directories and the\n"
        "recycle folder."),
    examples = [
        ("Create the rclone remote for the Hetzner locker", "sync_tool -a Init -l Hetzner"),
        ("Copy everything from the remote into the local locker", "sync_tool -a Download -l Hetzner"),
        ("Show the paths an upload would use without running it", "sync_tool -a Upload -l Hetzner -p -v"),
        ("Make the remote an exact copy of the local locker, deleting remote-only files", "sync_tool -a Push -l Gdrive"),
        ("Make the local locker an exact copy of the remote, deleting local-only files", "sync_tool -a Pull -l Gdrive"),
        ("Merge changes both ways, rebuilding bisync's state from scratch", "sync_tool -a Merge -l Gdrive -e"),
        ("Write difference lists to the current directory, comparing sizes only", "sync_tool -a Diff -l Hetzner -q"),
        ("Act on difference lists written by an earlier Diff", "sync_tool -a DiffSync -l Hetzner --diff_dir /path/to/diff/files"),
        ("Diff, upload local-only files and recycle remote-only ones", "sync_tool -a DiffSync -l Hetzner -r"),
        ("Permanently delete the remote recycle folder", "sync_tool -a EmptyRecycle -l Hetzner"),
        ("List every file on the remote", "sync_tool -a List -l Hetzner"),
        ("Mount the remote so other tools can read it", "sync_tool -a Mount -l Hetzner"),
        ("Download without the locker's configured exclusions", "sync_tool -a Download -l Hetzner --excludes \"Testing/**\""),
    ],
    notes = [
        "`-l` has no default and must name a remote locker; the default action is `Init`.",
        "The local side is always the `Local` locker's directory, which must exist for the transfer and diff actions.",
        "`Merge` needs an `RCLONE_TEST` file in both roots (`--check-access`), and the first run for a pair needs `-e`.",
        "`--excludes` replaces the configured list rather than adding to it. An empty value means the configured list is used.",
        "`Diff` writes its lists relative to the current directory unless the `--diff_*_path` options give full paths. For `DiffSync` those options are file names inside `--diff_dir`.",
        "`Mount` does nothing when the mount path already has files in it, since it assumes the remote is mounted. With `-v` rclone logs to `/tmp/rclone.log`.",
        "Under `-p` no rclone command is run at all, so a pretend run only shows the preview.",
    ],
    see_also = ["backup_tool", "upload_game_files", "master_backup", "locker_sync_tool"],
    section = "Backups & Lockers")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.RemoteActionType,
    default = config.RemoteActionType.INIT,
    description = "Operation to run; see the list above")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Remote locker to operate on")
parser.add_string_argument(args = ("--excludes"), default = "", description = "Comma-separated rclone exclude patterns to use instead of the locker's configured `excluded_dirs`")
parser.add_group("Diff files")
parser.add_string_argument(args = ("--diff_combined_path"), default = "diff_combined.txt", description = "File listing every path with a marker: `=` same, `*` differs, `+` local only, `-` remote only, `!` error")
parser.add_string_argument(args = ("--diff_intersected_path"), default = "diff_intersected.txt", description = "File listing paths present on both sides whose contents differ")
parser.add_string_argument(args = ("--diff_missing_src_path"), default = "diff_missing_src.txt", description = "File listing paths only on the remote (missing locally)")
parser.add_string_argument(args = ("--diff_missing_dest_path"), default = "diff_missing_dest.txt", description = "File listing paths only in the local locker (missing on the remote)")
parser.add_string_argument(args = ("--diff_error_path"), default = "diff_errors.txt", description = "File listing paths that could not be compared; written by `Diff` only")
parser.add_string_argument(args = ("--diff_dir"), description = "For `DiffSync`: directory holding the lists from an earlier `Diff`; when omitted a fresh diff is run into a temporary directory")
parser.add_group("Behavior")
parser.add_boolean_argument(args = ("-e", "--resync"), description = "For `Merge`: pass `--resync` to bisync, needed on the first run or after bisync's state is lost")
parser.add_boolean_argument(args = ("-i", "--interactive"), description = "Pass `--interactive` to rclone so it asks before each change; applies to the transfer actions and `DiffSync`")
parser.add_boolean_argument(args = ("-q", "--quick"), description = "For `Diff` and `DiffSync`: compare file sizes only instead of hashes")
parser.add_boolean_argument(args = ("-r", "--recycle_missing"), description = "For `DiffSync`: move remote-only files into the remote recycle folder instead of downloading them")
parser.add_string_argument(args = ("--recycle_folder"), default = ".recycle_bin", description = "Name of the recycle folder at the remote locker's root, used by `DiffSync`, `EmptyRecycle` and excluded from diffs")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get locker info
    locker_info = lockerinfo.LockerInfo(args.locker_type)
    if not locker_info:
        logger.log_error("Invalid locker", quit_program = True)

    # Sync options
    remote_type = locker_info.get_type()
    remote_name = locker_info.get_name()
    remote_path = locker_info.get_remote_path()
    remote_token = locker_info.get_token()
    remote_config = locker_info.get_config()
    local_path = lockerinfo.LockerInfo(config.LockerType.LOCAL).get_mount_path()
    mount_path = locker_info.get_mount_path()
    mount_flags = locker_info.get_mount_flags()

    # Actions that require local/mount path to exist
    actions_requiring_local_path = [
        config.RemoteActionType.DOWNLOAD,
        config.RemoteActionType.UPLOAD,
        config.RemoteActionType.PULL,
        config.RemoteActionType.PUSH,
        config.RemoteActionType.MERGE,
        config.RemoteActionType.DIFF,
        config.RemoteActionType.DIFFSYNC,
    ]

    # Validate local path exists for actions that need it
    if args.action in actions_requiring_local_path:
        if not local_path:
            logger.log_error("Action '%s' requires a local path, but none is configured for the Local locker" % (
                args.action), quit_program = True)
        if not paths.does_path_exist(local_path):
            logger.log_error("Action '%s' requires the local locker path to exist: %s" % (
                args.action, local_path), quit_program = True)

    # Get excludes from CLI or locker config
    if args.excludes:
        excludes = [e.strip() for e in args.excludes.split(",") if e.strip()]
    else:
        excludes = locker_info.get_excluded_dirs()

    # Show preview
    if not args.no_preview:
        details = []
        if local_path:
            details.append("Local: %s" % local_path)
        if remote_path:
            details.append("Remote: %s:%s" % (remote_name, remote_path))
        if mount_path:
            details.append("Mount: %s" % mount_path)
        if not prompts.prompt_for_preview("Sync %s (%s)" % (args.action, args.locker_type), details):
            logger.log_warning("Operation cancelled by user")
            return

    # Init sync
    if args.action == config.RemoteActionType.INIT:
        sync.setup_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_token = remote_token,
            remote_config = remote_config,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Download files
    elif args.action == config.RemoteActionType.DOWNLOAD:
        sync.download_files_from_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Upload files
    elif args.action == config.RemoteActionType.UPLOAD:
        sync.upload_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Pull files
    elif args.action == config.RemoteActionType.PULL:
        sync.pull_files_from_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Push files
    elif args.action == config.RemoteActionType.PUSH:
        sync.push_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Merge files
    elif args.action == config.RemoteActionType.MERGE:
        sync.merge_files_both_ways(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            resync = args.resync,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff files
    elif args.action == config.RemoteActionType.DIFF:
        diff_excludes = list(excludes)
        if args.recycle_folder:
            diff_excludes.append(args.recycle_folder + "/**")
        sync.diff_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = diff_excludes,
            diff_combined_path = args.diff_combined_path,
            diff_intersected_path = args.diff_intersected_path,
            diff_missing_src_path = args.diff_missing_src_path,
            diff_missing_dest_path = args.diff_missing_dest_path,
            diff_error_path = args.diff_error_path,
            quick = args.quick,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Diff sync files
    elif args.action == config.RemoteActionType.DIFFSYNC:
        diffsync_excludes = list(excludes)
        if args.recycle_folder:
            diffsync_excludes.append(args.recycle_folder + "/**")
        sync.diff_sync_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = diffsync_excludes,
            diff_dir = args.diff_dir,
            diff_combined_file = args.diff_combined_path,
            diff_intersected_file = args.diff_intersected_path,
            diff_missing_src_file = args.diff_missing_src_path,
            diff_missing_dest_file = args.diff_missing_dest_path,
            recycle_missing = args.recycle_missing,
            recycle_folder = args.recycle_folder,
            quick = args.quick,
            interactive = args.interactive,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Empty recycle bin
    elif args.action == config.RemoteActionType.EMPTYRECYCLE:
        sync.empty_recycle_bin(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            recycle_folder = args.recycle_folder,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # List files
    elif args.action == config.RemoteActionType.LIST:
        sync.list_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            recursive = True,
            only_directories = False,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Mount files
    elif args.action == config.RemoteActionType.MOUNT:
        sync.mount_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            mount_path = mount_path,
            no_cache = "no_cache" in mount_flags,
            no_checksum = "no_checksum" in mount_flags,
            no_modtime = "no_modtime" in mount_flags,
            no_seek = "no_seek" in mount_flags,
            read_only = "read_only" in mount_flags,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
