#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.hardening as hardening
import joybox.logger as logger
import joybox.runtime as runtime
import joybox.serverinfo as serverinfo
import joybox.setup as setup
import joybox.system as system
from joybox import runoptions

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Check that a server's hardening actually took effect.")
parser.add_string_argument(
    args = ("-s", "--server"),
    description = "Server entry to check over ssh; omit to check this machine")
parser.add_string_argument(args = ("-d", "--domain"), description = "Domain to burst test")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Connect to whatever is being checked
    connection = serverinfo.get_connection(
        server_index = args.server,
        flags = runoptions.RunFlags(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure))
    if not connection:
        logger.log_error(
            "No host configured for server %s" % args.server, quit_program = True)
    connection.setup()
    try:
        results = hardening.verify_hardening(
            connection = connection,
            domain = args.domain,
            verbose = False)
    finally:
        connection.teardown()

    # Report
    print(hardening.format_results(results))
    print()
    failures = hardening.count_failures(results)
    if failures == 0:
        print("All checks passed.")
    else:
        print("%d check(s) failed." % failures)

    # The exit code is the failure count, so this works as a gate
    runtime.quit_program(failures)

# Start
if __name__ == "__main__":
    system.run_main(main)
