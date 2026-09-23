#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.lockerinfo as lockerinfo
import joybox.sync as sync
import joybox.paths as paths
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Setup argument parser
parser = arguments.ArgumentParser(
    description = "Rebuild a remote locker's hash sidecar database from local content.",
    details = (
        "The hash sidecar is a SQLite database, `.locker_hashes.db`, at the root of a remote\n"
        "locker. It records the path, MD5, size and modification time of each file as it is on\n"
        "the local side (before any encryption). Remotes that cannot hash files themselves,\n"
        "such as the SFTP-based Hetzner locker, rely on it: `locker_sync_tool` and\n"
        "`master_backup` read it instead of asking the remote, so it has to be current for\n"
        "their comparisons to be right.\n"
        "\n"
        "The tool downloads the existing database if there is one, hashes the source locker's\n"
        "files (or the `--path` subtree), writes the new entries over any existing ones for the\n"
        "same paths, and uploads the database back to the destination locker's root. Hidden\n"
        "directories and the destination locker's configured `excluded_dirs` are skipped.\n"
        "Directories with more than 500 files or 10 GB are hashed one at a time first; the\n"
        "rest are hashed `--parallel_dirs` at a time.\n"
        "\n"
        "`--skip_existing` is keyed on path, not content: a file that already has an entry\n"
        "keeps its old row even if the file has changed. Every file is still hashed; only the\n"
        "database write is skipped. Use it to add new files quickly, and run without it when\n"
        "files may have changed. If the existing database cannot be downloaded, the run\n"
        "starts from an empty one, so nothing is skipped."),
    examples = [
        ("Rebuild the Hetzner sidecar from the local locker", "rebuild_hash_sidecars -l Local -d Hetzner -v"),
        ("Show what would be hashed without uploading anything", "rebuild_hash_sidecars -p -v"),
        ("Add entries only for files not yet in the database", "rebuild_hash_sidecars -s -v"),
        ("Rehash one subtree", "rebuild_hash_sidecars --path \"Gaming/Roms\" -v"),
        ("Start from an empty database and rehash the whole locker", "rebuild_hash_sidecars -c -v"),
    ],
    notes = [
        "Entries for files that were deleted locally stay in the database until it is rebuilt with `-c`.",
        "`-c` deletes the whole database at the destination root, even when `--path` limits the rehash to a subtree, so combine them only when you mean to drop every other entry.",
        "Peak memory is about `parallel_dirs` x `parallel_files` x the hashing chunk size; the preview shows the figure.",
        "Hetzner's SFTP shell has no usable `md5sum`, so an rclone remote with `md5sum_command` set fails to verify the upload, reports `corrupted on transfer`, and deletes the uploaded database. Set `disable_hashcheck = true` on that remote and remove any `md5sum_command`/`sha1sum_command`; the Hetzner template in the rclone setup already does this.",
        "`master_backup` refreshes the sidecar after each backup, so this tool is mainly for repairs and first-time setup.",
    ],
    see_also = ["find_missing_hash_sidecars", "master_backup", "locker_sync_tool", "sync_tool"],
    section = "Backups & Lockers")
parser.add_group("Lockers")
parser.add_enum_argument(
    args = ("-l", "--source_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.LOCAL,
    description = "Locker whose mount path holds the files to hash")
parser.add_enum_argument(
    args = ("-d", "--dest_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Remote locker whose `.locker_hashes.db` is rebuilt; must be a configured rclone remote")
parser.add_string_argument(
    args = ("--path",),
    default = "",
    description = "Subtree relative to the locker root to rehash, e.g. `Gaming/Roms`; the whole locker when empty")
parser.add_group("Behavior")
parser.add_boolean_argument(
    args = ("-c", "--clear"),
    description = "Delete the existing database at the destination root before rebuilding")
parser.add_boolean_argument(
    args = ("-s", "--skip_existing"),
    description = "Leave existing database entries untouched and add only paths that have none")
parser.add_integer_argument(
    args = ("-r", "--parallel_dirs"),
    default = 4,
    description = "Number of directories hashed at the same time")
parser.add_integer_argument(
    args = ("-f", "--parallel_files"),
    default = 4,
    description = "Number of files hashed at the same time within each directory")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get source locker info
    source_info = lockerinfo.LockerInfo(args.source_locker)
    if not source_info:
        logger.log_error("Could not get locker info for %s" % args.source_locker, quit_program = True)

    # Get dest locker info
    dest_info = lockerinfo.LockerInfo(args.dest_locker)
    if not dest_info:
        logger.log_error("Could not get locker info for %s" % args.dest_locker, quit_program = True)

    # Get paths
    source_root = source_info.get_mount_path()
    dest_name = dest_info.get_name()
    dest_type = dest_info.get_type()
    dest_root = dest_info.get_remote_path() or ""
    dest_path = dest_root

    # Get excludes from destination locker config
    excludes = dest_info.get_excluded_dirs()

    # Apply subpath if specified
    source_path = source_root
    if args.path:
        source_path = paths.join_paths(source_root, args.path)
        dest_path = paths.join_paths(dest_root, args.path).replace("\\", "/")

    # Validate
    if not paths.does_path_exist(source_path):
        logger.log_error("Source path not accessible: %s" % source_path, quit_program = True)
    if not sync.is_remote_configured(dest_name, dest_type):
        logger.log_error("Remote '%s' is not configured" % dest_name, quit_program = True)

    # Show preview
    if not args.no_preview:
        db_path = sync.get_hash_database_path(dest_root)
        max_memory_bytes = args.parallel_dirs * args.parallel_files * config.hash_chunk_size
        max_memory_mb = max_memory_bytes / (1024 * 1024)
        details = [
            "Source: %s" % source_path,
            "Destination: %s:%s" % (dest_name, db_path),
            "Parallel dirs: %d, Parallel files: %d" % (args.parallel_dirs, args.parallel_files),
            "Max memory usage: %.0f MB (%d × %d × %d MB chunk)" % (
                max_memory_mb, args.parallel_dirs, args.parallel_files,
                config.hash_chunk_size // (1024 * 1024))
        ]
        if excludes:
            details.append("Excluded dirs: %s" % ", ".join(excludes))
        if args.clear:
            details.append("Clear existing sidecars: Yes")
        if args.skip_existing:
            details.append("Skip existing sidecars: Yes")
        if not prompts.prompt_for_preview("Rebuild hash sidecars", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Clear existing sidecars if requested (always clear at dest root)
    if args.clear:
        logger.log_info("Clearing existing sidecars...")
        if not sync.clear_hash_sidecar_files(
            remote_name = dest_name,
            remote_type = dest_type,
            remote_path = dest_root,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure):
            logger.log_error("Failed to clear sidecars")
            sys.exit(1)

    # Rebuild
    success = sync.upload_hash_sidecar_files(
        remote_name = dest_name,
        remote_type = dest_type,
        remote_path = dest_path,
        local_path = source_path,
        local_root = dest_root,
        excludes = excludes,
        skip_existing = args.skip_existing,
        parallel_dirs = args.parallel_dirs,
        parallel_files = args.parallel_files,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if success:
        logger.log_info("Rebuild complete")
    else:
        logger.log_error("Rebuild failed")
        sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
