#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.bootstrap.provision as provision
import joybox.logger as logger
import joybox.runtime as runtime
import joybox.serverinfo as serverinfo
import joybox.setup as setup
import joybox.system as system
from joybox import runoptions

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Take a server entry from nothing to deployed, hardened and verified.",
    details = (
        "Runs every step of setting up a server from `[UserData.Servers]` in `~/JoyBox.ini`,\n"
        "from this machine over SSH. The same stages run against a real host and against the\n"
        "local test guest; each one checks what is already done, so running it again resumes\n"
        "after a failure rather than starting over.\n"
        "\n"
        "Stages, in order:\n"
        "\n"
        "- `vm`: only when the entry names a test guest (`server_<n>_vm`). Builds it with\n"
        "  `testvm`'s defaults at the entry's address, or starts it; waits for first boot and\n"
        "  snapshots it as `provision-fresh`; points the domain and its subdomains at it in\n"
        "  `/etc/hosts`.\n"
        "- `login`: if the account cannot log in with the entry's key, logs in as root with\n"
        "  that key, creates the account with root's authorised keys, and sets its password\n"
        "  from `server_<n>_pass` when there is one.\n"
        "- `day0`: copies `Bootstrap/scripts` and `Bootstrap/managers` from this checkout and\n"
        "  runs, as root, the sudoers, docker, nginx and htpasswd setup, then the Storage Box\n"
        "  mount when `server_<n>_storage_user` and `_host` are set, or local storage when\n"
        "  not. Skipped once root login is closed.\n"
        "- `deploy`: the same as `bootstrap.py -a setup -t remote_ubuntu -s <n>`, for\n"
        "  `--components` or every component. Trusts mkcert's local authority first when the\n"
        "  entry uses `tls_mode = mkcert`.\n"
        "- `sshd`: proves the account's key login, snapshots a test guest as `pre-sshd`, runs\n"
        "  the sshd hardening that closes root and password login, then proves the key login\n"
        "  again. A test guest that loses it is reverted.\n"
        "- `verify`: the `verify_server` checks, as the account.\n"
        "\n"
        "Secrets come from the entry, so they can be `op://` references: `_htpasswd_pass` for\n"
        "the admin pages, `_storage_pass` for the Storage Box, and `_pass` for the account.\n"
        "They reach the server as files only root can read, and are removed after use."),
    examples = [
        ("Provision the local test guest in server entry 1", "provision_server --server 1"),
        ("Provision a real server with only some components", "provision_server -s 0 --components nginx certbot wordpress fitlog"),
        ("Redeploy and re-verify without the earlier stages", "provision_server -s 1 --stages deploy verify"),
        ("Show what would run", "provision_server -s 1 -p"),
    ],
    notes = [
        "Needs paramiko on this machine; `python3 bootstrap.py -a setup -t local_ubuntu --components python` installs it.",
        "A real host must accept root with the entry's key on first contact, as a freshly ordered server does when given that key.",
        "Root login is closed by the `sshd` stage, so on a hardened server the `login` and `day0` stages only confirm the account and move on.",
        "The exit code is 0 on success, the number of failed checks when only `verify` fails, and 1 when an earlier stage fails.",
    ],
    see_also = ["testvm", "verify_server"],
    section = "Servers & Machines")
parser.add_integer_argument(args = ("-s", "--server"), description = "Index of the server entry under `[UserData.Servers]`")
parser.add_string_list_argument(args = ("-c", "--components"), several_per_flag = True, description = "Components to deploy; every remote component when omitted")
parser.add_string_list_argument(args = ("--stages"), several_per_flag = True, description = "Stages to run, from `vm`, `login`, `day0`, `deploy`, `sshd` and `verify`; all of them when omitted")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Check the inputs before touching anything; a dropped word could silently
    # skip a stage or a component
    if unknown:
        logger.log_error("Unexpected arguments: %s" % " ".join(unknown), quit_program = True)
    if args.server is None:
        logger.log_error("--server is required", quit_program = True)
    stages = args.stages or provision.STAGES
    unknown_stages = [stage for stage in stages if stage not in provision.STAGES]
    if unknown_stages:
        logger.log_error("Unknown stage(s): %s" % ", ".join(unknown_stages), quit_program = True)
    server = serverinfo.ServerInfo(args.server)
    if not server.is_configured():
        logger.log_error("No host configured for server %s" % args.server, quit_program = True)
    missing = provision.get_missing_settings(server, stages)
    if missing:
        logger.log_error("Set these in ~/JoyBox.ini first: %s" % ", ".join(missing), quit_program = True)
    try:
        import paramiko
    except ImportError:
        logger.log_error(
            "paramiko is not installed; run: python3 bootstrap.py -a setup "
            "-t local_ubuntu --components python", quit_program = True)

    # Plan
    provisioner = provision.Provisioner(
        server = server,
        components = args.components,
        stages = stages,
        flags = runoptions.RunFlags(
            verbose = args.verbose,
            pretend_run = False,
            exit_on_failure = args.exit_on_failure))
    for line in provisioner.describe():
        logger.log_info(line)
    if args.pretend_run:
        return

    # Run
    serverinfo.select_server(args.server)
    if provisioner.run():
        logger.log_info("Server %s is provisioned" % args.server)
        return
    if provisioner.verify_failures and provisioner.stages[-1] == "verify":
        runtime.quit_program(provisioner.verify_failures)
    runtime.quit_program(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
