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
import joybox.masterbackup as masterbackup
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Setup argument parser
parser = arguments.ArgumentParser(
    description = "Back up the local locker to one or more remote lockers in one unattended run.",
    details = (
        "Treats the source locker (normally `Local`) as the authoritative copy and pushes new\n"
        "and changed files to each destination locker, by default `Hetzner` and `Gdrive`. It\n"
        "asks for one confirmation and then runs without prompting. It is additive by default:\n"
        "files that exist only on a destination are kept unless `--recycle_orphans` is given.\n"
        "\n"
        "For each destination it:\n"
        "\n"
        "1. Builds an MD5 hash map of the source and of the destination and compares them by\n"
        "   relative path. Local lockers are hashed on disk; remotes are listed with\n"
        "   `rclone lsjson --hash`, and SFTP remotes such as Hetzner are read from their\n"
        "   `.locker_hashes.db` sidecar instead.\n"
        "2. Uploads files missing from the destination or whose hash differs. Plain files go up\n"
        "   in one `rclone copy --files-from`. For a destination marked `encrypted` in its\n"
        "   locker settings, files are encrypted into a staging tree in the cache directory and\n"
        "   uploaded in batches of about 4 GiB.\n"
        "3. Refreshes the destination's hash sidecar from the local content, once, when the\n"
        "   source is a local locker and the destination is an SFTP remote.\n"
        "\n"
        "Each destination's configured `excluded_dirs` are left out of both the comparison and\n"
        "the upload. This is the unattended form of `locker_sync_tool`."),
    examples = [
        ("Back up the local locker to Hetzner and Gdrive", "master_backup"),
        ("Show what would be uploaded without uploading anything", "master_backup -p -v"),
        ("Back up to Hetzner only", "master_backup -r Hetzner"),
        ("Also move remote files that no longer exist locally into the recycle bin", "master_backup --recycle_orphans"),
        ("Rehash everything instead of using the cached hash maps", "master_backup --skip_cache"),
    ],
    notes = [
        "Hash maps are cached per locker for 24 hours, including the source's. Files changed locally since the cached map was built are not seen until it expires, so use `--skip_cache` after recent changes.",
        "A pretend run still hashes local lockers and writes their cache, so the real run that follows can reuse it.",
        "`--recycle_orphans` moves orphans into the destination's `.recycle_bin`; nothing is hard-deleted. The recycle bin itself is never compared.",
        "The sidecar refresh is skipped for a destination when any of its uploads failed, so the next run finds and retries the missing files.",
        "The Hetzner rclone remote needs `disable_hashcheck = true`, since SFTP cannot run `md5sum` to verify transfers; the rclone config JoyBox generates sets it.",
    ],
    see_also = ["locker_sync_tool", "rebuild_hash_sidecars", "find_missing_hash_sidecars", "sync_tool", "backup_tool"],
    section = "Backups & Lockers")
parser.add_enum_argument(
    args = ("-l", "--local_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.LOCAL,
    description = "Locker to back up from; its content is treated as authoritative")
parser.add_string_argument(
    args = ("-r", "--remote_lockers"),
    default = "Hetzner,Gdrive",
    description = "Comma-separated locker names to back up to; unknown names are skipped with a warning")
parser.add_boolean_argument(
    args = ("--no_rebuild_sidecars",),
    description = "Do not refresh the SFTP destinations' hash sidecars after uploading")
parser.add_boolean_argument(
    args = ("--recycle_orphans",),
    description = "Move destination files that are missing from the source into the destination's `.recycle_bin`; by default they are kept")
parser.add_boolean_argument(
    args = ("--skip_cache",),
    description = "Rebuild every hash map instead of reusing one cached within the last 24 hours")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Parse remote locker types
    remote_locker_types = []
    for locker_str in args.remote_lockers.split(","):
        locker_str = locker_str.strip()
        if locker_str:
            locker_type = config.LockerType.from_string(locker_str)
            if locker_type:
                remote_locker_types.append(locker_type)
            else:
                logger.log_warning("Unknown locker type: %s" % locker_str)
    if not remote_locker_types:
        logger.log_error("No valid remote locker types specified", quit_program = True)

    # Show preview
    if not args.no_preview:
        local_name = lockerinfo.LockerInfo(args.local_locker).get_locker_name()
        details = [
            "Source (authoritative): %s" % local_name,
            "Destinations: %s" % ", ".join([lt.val() for lt in remote_locker_types]),
            "Orphan handling: %s" % ("recycle to .recycle_bin" if args.recycle_orphans else "keep (additive only)"),
            "Rebuild hash sidecars: %s" % ("No" if args.no_rebuild_sidecars else "Yes"),
            "Phase 1: hash source + each destination, compute differences",
            "Phase 2: upload new/changed files to each destination",
        ]
        if not args.no_rebuild_sidecars:
            details.append("Phase 3: refresh remote hash sidecars (e.g. Hetzner)")
        if not prompts.prompt_for_preview("Master backup", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Run backup
    success = masterbackup.run_master_backup(
        local_locker_type = args.local_locker,
        remote_locker_types = remote_locker_types,
        rebuild_sidecars = not args.no_rebuild_sidecars,
        recycle_orphans = args.recycle_orphans,
        skip_cache = args.skip_cache,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if success:
        logger.log_info("Master backup completed successfully")
    else:
        logger.log_error("Master backup failed")
        sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
