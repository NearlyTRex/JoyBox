#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.command as command
import joybox.hostsfile as hostsfile
import joybox.logger as logger
import joybox.setup as setup
import joybox.system as system
import joybox.virtualmachine as virtualmachine

# Parse arguments
parser = arguments.ArgumentParser(description = "Manage the local rehearsal virtual machine.")
parser.add_string_argument(
    args = ("action",),
    description = "create, destroy, snapshot, revert, snapshots, ip, console or hosts")
parser.add_string_argument(
    args = ("-n", "--name"),
    default = virtualmachine.DEFAULT_NAME,
    description = "Virtual machine name")
parser.add_string_argument(args = ("-s", "--snapshot"), description = "Snapshot name")
parser.add_string_argument(args = ("-u", "--username"), description = "Guest account name")
parser.add_string_argument(args = ("-k", "--ssh_key"), description = "SSH public key file")
parser.add_string_argument(args = ("-d", "--domain"), default = "joybox.test", description = "Test domain")
parser.add_string_argument(args = ("--release"), default = virtualmachine.DEFAULT_RELEASE, description = "Ubuntu release")
parser.add_integer_argument(args = ("--memory"), default = virtualmachine.DEFAULT_MEMORY, description = "Memory in MB")
parser.add_integer_argument(args = ("--vcpus"), default = virtualmachine.DEFAULT_VCPUS, description = "Processor count")
parser.add_integer_argument(args = ("--disk_size"), default = virtualmachine.DEFAULT_DISK_SIZE, description = "Disk size in GB")
parser.add_boolean_argument(args = ("--remove"), description = "Remove the hosts entries instead of adding them")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Create the virtual machine
    if args.action == "create":
        success = virtualmachine.create_vm(
            vm_name = args.name,
            username = args.username,
            ssh_key_file = args.ssh_key,
            memory = args.memory,
            vcpus = args.vcpus,
            disk_size = args.disk_size,
            release = args.release,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Unable to create the virtual machine", quit_program = True)
        logger.log_info("Waiting for an address; run 'testvm.py ip' once it has one")

    # Destroy the virtual machine
    elif args.action == "destroy":
        virtualmachine.destroy_vm(
            vm_name = args.name,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Take a snapshot before a risky step
    elif args.action == "snapshot":
        virtualmachine.snapshot_vm(
            vm_name = args.name,
            snapshot_name = args.snapshot,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Go back to a snapshot
    elif args.action == "revert":
        virtualmachine.revert_vm(
            vm_name = args.name,
            snapshot_name = args.snapshot,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # List the snapshots
    elif args.action == "snapshots":
        for snapshot in virtualmachine.list_snapshots(args.name, verbose = args.verbose):
            logger.log_info(snapshot)

    # Report the address
    elif args.action == "ip":
        address = virtualmachine.get_vm_ip(args.name, verbose = args.verbose)
        if not address:
            logger.log_error("No address yet for '%s'" % args.name, quit_program = True)
        print(address)

    # Attach to the console, the way back in after an ssh lockout
    elif args.action == "console":
        command.run_interactive_command(
            cmd = virtualmachine.get_console_command(args.name),
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Point the test domain at the virtual machine
    elif args.action == "hosts":
        if args.remove:
            hostsfile.remove_entries(
                verbose = True,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        else:
            address = virtualmachine.get_vm_ip(args.name, verbose = args.verbose)
            if not address:
                logger.log_error("No address yet for '%s'" % args.name, quit_program = True)
            hostsfile.set_entries(
                address = address,
                domain = args.domain,
                verbose = True,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Unknown action
    else:
        logger.log_error("Unknown action '%s'" % args.action, quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
