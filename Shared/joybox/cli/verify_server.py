# Imports
from joybox import arguments
from joybox import hardening
from joybox.bootstrap import provision
from joybox import logger
from joybox import runtime
from joybox import setup
from joybox import system

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "verify_server")
    parser.add_string_argument(
        args = ("-s", "--server"),
        description = "Index of the `server_<n>_*` entry to check over SSH, e.g. `0`; this machine when omitted")
    parser.add_string_argument(args = ("-d", "--domain"), description = "Domain to send a burst of HTTPS requests to, to prove rate limiting refuses them; no burst when omitted")
    parser.add_common_arguments()
    return parser

# Run the hardening checks against a server entry or this machine and exit with the failure count
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Run the checks against whatever is being checked
    results = provision.verify_server(
        server_index = args.server,
        domain = args.domain,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

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

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
