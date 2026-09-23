#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.lockersync as lockersync
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Setup argument parser
parser = arguments.ArgumentParser(
    description = "Sync a primary locker to one or more secondary lockers, reviewing each change in an editor.",
    details = (
        "Treats one locker as authoritative (the primary, `Hetzner` by default) and brings each\n"
        "secondary locker (`Gdrive,External` by default) into line with it. For each secondary\n"
        "it:\n"
        "\n"
        "1. Builds an MD5 hash map of the primary and the secondary. Local lockers are hashed\n"
        "   on disk; remotes are listed with `rclone lsjson --hash`, falling back to the\n"
        "   `.locker_hashes.db` sidecar when the remote returns no hashes. SFTP remotes such as\n"
        "   Hetzner always use the sidecar.\n"
        "2. Works out the actions: COPY for files only on the primary, UPDATE for files whose\n"
        "   hash differs, and RECYCLE for orphans that exist only on the secondary.\n"
        "3. Opens your editor with the actions. COPY and UPDATE lines are active; RECYCLE lines\n"
        "   are commented out, so orphans are kept unless you uncomment them. Delete or comment\n"
        "   a line to skip it; delete every line to skip that secondary.\n"
        "4. Runs the approved actions, one batched transfer per kind of cryption.\n"
        "\n"
        "Files are decrypted when going from a locker marked `encrypted` to one that is not\n"
        "(with the primary's passphrase) and encrypted the other way (with the secondary's).\n"
        "Each secondary's configured `excluded_dirs` are left out of both the comparison and the\n"
        "writes, and its `.recycle_bin` is never compared.\n"
        "\n"
        "After a successful sync, when the primary is a local locker and the secondary is an\n"
        "SFTP remote, the secondary's hash sidecar is refreshed from the local content. For an\n"
        "unattended, additive local-to-remote backup use `master_backup`."),
    examples = [
        ("Sync Hetzner to Gdrive and External", "locker_sync_tool"),
        ("Show the actions without transferring anything", "locker_sync_tool -p -v"),
        ("Sync the local locker to Gdrive only", "locker_sync_tool -l Local -s Gdrive"),
        ("Rehash everything instead of using the cached hash maps", "locker_sync_tool --skip_cache -v"),
        ("Delete all cached hash maps, then sync", "locker_sync_tool --clear_cache"),
    ],
    notes = [
        "Hash maps are cached per locker for 24 hours, including the primary's, so recent changes are not seen until the cache expires unless `--skip_cache` or `--clear_cache` is given. Caches are written even on pretend runs.",
        "After a sync the secondary's cached map is updated with the files just transferred, so a re-run within the cache window does not transfer them again.",
        "Recycled orphans go to the secondary's `.recycle_bin`; nothing is hard-deleted.",
        "For SFTP remotes the comparison is only as accurate as the sidecar. Keep it current with `master_backup` or `rebuild_hash_sidecars`.",
        "There is no preview prompt, so `--no-preview` has no effect; the editor is the review step.",
    ],
    see_also = ["master_backup", "rebuild_hash_sidecars", "find_missing_hash_sidecars", "sync_tool"],
    section = "Backups & Lockers")
parser.add_enum_argument(
    args = ("-l", "--primary_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Authoritative locker that the secondaries are brought in line with")
parser.add_string_argument(
    args = ("-s", "--secondary_lockers"),
    default = "Gdrive,External",
    description = "Comma-separated locker names to update; unknown names are skipped with a warning")
parser.add_boolean_argument(
    args = ("--skip_cache",),
    description = "Rebuild every hash map instead of reusing one cached within the last 24 hours")
parser.add_boolean_argument(
    args = ("--clear_cache",),
    description = "Delete every cached hash map before starting, not just those of the lockers in this run")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Parse secondary locker types
    secondary_locker_types = []
    for locker_str in args.secondary_lockers.split(","):
        locker_str = locker_str.strip()
        if locker_str:
            locker_type = config.LockerType.from_string(locker_str)
            if locker_type:
                secondary_locker_types.append(locker_type)
            else:
                logger.log_warning("Unknown locker type: %s" % locker_str)
    if not secondary_locker_types:
        logger.log_error("No valid secondary locker types specified", quit_program = True)

    # Clear cache if requested
    if args.clear_cache:
        logger.log_info("Clearing hash map cache...")
        lockersync.clear_cache()

    # Log configuration
    logger.log_info("Primary locker: %s" % args.primary_locker)
    logger.log_info("Secondary lockers: %s" % ", ".join([lt.val() for lt in secondary_locker_types]))

    # Run sync
    success = lockersync.sync_lockers(
        primary_locker_type = args.primary_locker,
        secondary_locker_types = secondary_locker_types,
        skip_cache = args.skip_cache,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if success:
        logger.log_info("Locker sync completed successfully")
    else:
        logger.log_error("Locker sync failed")
        sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
