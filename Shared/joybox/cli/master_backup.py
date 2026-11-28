# Imports
from joybox import config
from joybox import system
from joybox import masterbackup
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "master_backup")
    parser.add_enum_argument(
        args = ("-l", "--local_locker"),
        arg_type = config.LockerType,
        default = config.LockerType.LOCAL,
        description = "Locker to back up from; its content is treated as authoritative")
    parser.add_string_argument(
        args = ("-r", "--remote_lockers"),
        default = "Hetzner,Gdrive",
        description = "Comma-separated locker names to back up to; an unknown name stops the run")
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
    return parser

# After one confirmation, push new and changed files from the source locker to each destination locker unattended
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Parse remote locker types
    remote_locker_types = masterbackup.parse_remote_locker_types(args.remote_lockers)

    # Show preview
    details = masterbackup.get_master_backup_preview(
        local_locker_type = args.local_locker,
        remote_locker_types = remote_locker_types,
        recycle_orphans = args.recycle_orphans,
        rebuild_sidecars = not args.no_rebuild_sidecars)
    if not prompts.confirm_preview(args.no_preview, "Master backup", details):
        return

    # Run backup
    masterbackup.run_master_backup_or_quit(
        local_locker_type = args.local_locker,
        remote_locker_types = remote_locker_types,
        rebuild_sidecars = not args.no_rebuild_sidecars,
        recycle_orphans = args.recycle_orphans,
        skip_cache = args.skip_cache,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
