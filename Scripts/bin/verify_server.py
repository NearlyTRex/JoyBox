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
    description = "Check that a server's hardening actually took effect.",
    details = (
        "Runs a set of checks against a server entry from `[UserData.Servers]` in\n"
        "`~/JoyBox.ini`, over the same SSH connection the bootstrap uses, or against this\n"
        "machine when `--server` is omitted. Nothing has to be installed on the target.\n"
        "\n"
        "Every check tests the effect rather than the configuration:\n"
        "\n"
        "- Container port bindings: no container publishes on `0.0.0.0`, and `ss` shows no\n"
        "  unexpected wildcard listeners.\n"
        "- Firewall: ufw is active, not just installed.\n"
        "- sshd: the effective config (`sshd -T`) has password authentication off and root\n"
        "  login restricted.\n"
        "- fail2ban: the `sshd` and `nginx-http-auth` jails are running.\n"
        "- Docker daemon: `userns-remap` and `no-new-privileges` are configured, and\n"
        "  userns-remap is active.\n"
        "- Rate limiting and headers: nginx defines and uses a `limit_req` zone and has\n"
        "  `server_tokens off`. With `--domain`, 40 requests are sent to it from the server\n"
        "  and at least one must be refused.\n"
        "- Unattended upgrades: the JoyBox config is present with automatic reboot enabled.\n"
        "\n"
        "A check whose tool is not installed on the target is reported as skipped rather than\n"
        "failed. The command exits with the number of failed checks, so it works as a gate."),
    examples = [
        ("Check server entry 0, including a rate-limit burst", "verify_server --server 0 --domain joybox.test"),
        ("Check this machine", "verify_server"),
        ("Check a server and fail a script if anything is wrong", "verify_server -s 1 -d example.com || echo \"hardening incomplete\""),
    ],
    notes = [
        "The sshd, firewall, fail2ban and nginx checks run their commands with sudo on the target.",
        "Without `--domain` the rate-limit burst is skipped; the domain is not read from `domain_name`.",
        "Each check is a function in `Shared/joybox/hardening.py` and can be run on its own from Python.",
    ],
    see_also = ["testvm"],
    section = "Servers & Machines")
parser.add_string_argument(
    args = ("-s", "--server"),
    description = "Index of the `server_<n>_*` entry to check over SSH, e.g. `0`; this machine when omitted")
parser.add_string_argument(args = ("-d", "--domain"), description = "Domain to send a burst of HTTPS requests to, to prove rate limiting refuses them; no burst when omitted")
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
