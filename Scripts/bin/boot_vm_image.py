#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.logger as logger
import joybox.setup as setup
import joybox.system as system
import joybox.virtualmachine as virtualmachine

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Boot an installer image in a throwaway machine, the way the target will.")
parser.add_string_argument(
    args = ("-n", "--name"),
    default = virtualmachine.DEFAULT_BOOT_NAME,
    description = "Machine name, which names its disk and its firmware variables")
parser.add_string_argument(
    args = ("-i", "--iso"),
    description = "Image to install from; leave it out to boot what was installed")
parser.add_string_argument(
    args = ("-b", "--boot_dir"),
    description = "Where to keep the disk and the firmware variables")
parser.add_integer_argument(
    args = ("-m", "--memory"),
    description = "Memory in MB")
parser.add_integer_argument(
    args = ("-c", "--vcpus"),
    description = "Processor count")
parser.add_integer_argument(
    args = ("-z", "--disk_size"),
    description = "Disk size in GB, used when the disk is made")
parser.add_integer_argument(
    args = ("-t", "--ssh_port"),
    description = "Local port forwarded to the machine's ssh")
parser.add_boolean_argument(
    args = ("-e", "--headless"),
    description = "Open no window, and put the console on this terminal")
parser.add_string_argument(
    args = ("-l", "--serial_file"),
    description = "With --headless, write the console to this file instead of the terminal")
parser.add_boolean_argument(
    args = ("-r", "--reset"),
    description = "Throw away the disk and start from nothing")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Boot it
    success = virtualmachine.boot_vm_image(
        vm_name = args.name,
        iso_file = args.iso,
        boot_dir = args.boot_dir,
        disk_size = args.disk_size,
        memory = args.memory,
        vcpus = args.vcpus,
        ssh_port = args.ssh_port,
        headless = args.headless,
        serial_file = args.serial_file,
        reset = args.reset,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Unable to boot the machine")
        return

    # Say what comes next
    if args.iso:
        logger.log_info("Boot what it installed with:")
        logger.log_info("  boot_vm_image -n %s" % args.name)

# Start
if __name__ == "__main__":
    system.run_main(main)
