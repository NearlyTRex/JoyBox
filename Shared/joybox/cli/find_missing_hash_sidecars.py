# Imports
from joybox import config
from joybox import system
from joybox import synctransfers
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "find_missing_hash_sidecars")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.HETZNER,
        description = "Remote locker to check")
    parser.add_string_argument(
        args = ("--path",),
        default = "",
        description = "Subtree relative to the locker root to list, e.g. `Gaming/Roms`; the whole locker when empty")
    parser.add_string_argument(
        args = ("-r", "--report"),
        default = "",
        description = "File to write the complete list of missing paths to; when omitted only the first 20 are logged")
    parser.add_common_arguments()
    return parser

# List the remote locker's files, under the subpath if given, that have no entry in its hash sidecar database
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Find files missing from the hash sidecar
    synctransfers.find_missing_hash_sidecars(
        locker_type = args.locker_type,
        subpath = args.path,
        report_file = args.report,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
