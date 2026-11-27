# Imports
from joybox import config
from joybox import system
from joybox import locker
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "sync_tool")
    parser.add_enum_argument(
        args = ("-a", "--action"),
        arg_type = config.RemoteActionType,
        default = config.RemoteActionType.INIT,
        description = "Operation to run; see the list above")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        description = "Remote locker to operate on")
    parser.add_string_argument(args = ("--excludes",), default = "", description = "Comma-separated rclone exclude patterns to use instead of the locker's configured `excluded_dirs`")
    parser.add_group("Diff files")
    parser.add_string_argument(args = ("--diff_combined_path",), default = "diff_combined.txt", description = "File listing every path with a marker: `=` same, `*` differs, `+` local only, `-` remote only, `!` error")
    parser.add_string_argument(args = ("--diff_intersected_path",), default = "diff_intersected.txt", description = "File listing paths present on both sides whose contents differ")
    parser.add_string_argument(args = ("--diff_missing_src_path",), default = "diff_missing_src.txt", description = "File listing paths only on the remote (missing locally)")
    parser.add_string_argument(args = ("--diff_missing_dest_path",), default = "diff_missing_dest.txt", description = "File listing paths only in the local locker (missing on the remote)")
    parser.add_string_argument(args = ("--diff_error_path",), default = "diff_errors.txt", description = "File listing paths that could not be compared; written by `Diff` only")
    parser.add_string_argument(args = ("--diff_dir",), description = "For `DiffSync`: directory holding the lists from an earlier `Diff`; when omitted a fresh diff is run into a temporary directory")
    parser.add_group("Behavior")
    parser.add_boolean_argument(args = ("-e", "--resync"), description = "For `Merge`: pass `--resync` to bisync, needed on the first run or after bisync's state is lost")
    parser.add_boolean_argument(args = ("-i", "--interactive"), description = "Pass `--interactive` to rclone so it asks before each change; applies to the transfer actions and `DiffSync`")
    parser.add_boolean_argument(args = ("-q", "--quick"), description = "For `Diff` and `DiffSync`: compare file sizes only instead of hashes")
    parser.add_boolean_argument(args = ("-r", "--recycle_missing"), description = "For `DiffSync`: move remote-only files into the remote recycle folder instead of downloading them")
    parser.add_string_argument(args = ("--recycle_folder",), default = ".recycle_bin", description = "Name of the recycle folder at the remote locker's root, used by `DiffSync`, `EmptyRecycle` and excluded from diffs")
    parser.add_common_arguments()
    return parser

# After a preview, run the chosen rclone action between the local locker and the remote locker; its outcome is the exit status
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get the remote locker and the local paths the action works on
    target = locker.get_remote_action_target(args.action, args.locker_type, args.excludes)

    # Show preview
    if not args.no_preview:
        details = locker.get_remote_action_preview(target)
        if not prompts.prompt_for_preview("Sync %s (%s)" % (args.action, args.locker_type), details):
            logger.log_warning("Operation cancelled by user")
            return None

    # Run the action; the outcome becomes the exit status
    return locker.run_remote_action(
        action = args.action,
        target = target,
        diff_paths = (args.diff_combined_path, args.diff_intersected_path, args.diff_missing_src_path,
            args.diff_missing_dest_path, args.diff_error_path),
        diff_dir = args.diff_dir,
        resync = args.resync,
        interactive = args.interactive,
        quick = args.quick,
        recycle_missing = args.recycle_missing,
        recycle_folder = args.recycle_folder,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
