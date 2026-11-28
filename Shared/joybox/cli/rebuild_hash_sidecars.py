# Imports
from joybox import config
from joybox import system
from joybox import synctransfers
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "rebuild_hash_sidecars")
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
        description = "Delete the existing database entries under `--path`, or the whole database when it is empty, before rebuilding")
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
    return parser

# After a preview, rebuild the remote locker's hash sidecar database from the local content, first clearing the old entries under the path when asked
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get the source, destination and excludes
    target = synctransfers.get_sidecar_rebuild_target(args.source_locker, args.dest_locker, args.path)

    # Show preview
    details = synctransfers.get_sidecar_rebuild_preview(
        target,
        parallel_dirs = args.parallel_dirs,
        parallel_files = args.parallel_files,
        clear = args.clear,
        skip_existing = args.skip_existing)
    if not prompts.confirm_preview(args.no_preview, "Rebuild hash sidecars", details):
        return

    # Rebuild, clearing the existing sidecar entries under the path first if requested
    synctransfers.rebuild_hash_sidecars(
        target,
        parallel_dirs = args.parallel_dirs,
        parallel_files = args.parallel_files,
        clear = args.clear,
        skip_existing = args.skip_existing,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
