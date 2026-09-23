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
    description = "Boot an installer image in a throwaway machine, the way the target will.",
    details = (
        "Runs qemu directly with UEFI firmware (OVMF), a blank qcow2 disk and the image in the\n"
        "drive, so an image from `build_autoinstall_iso` can be watched installing before it\n"
        "goes anywhere near real hardware. Qemu exits when the installer reboots, which is how\n"
        "you know it finished: the image is still in the drive, and a machine that carried on\n"
        "would boot it and start the install over. Run it again without `--iso` to boot what\n"
        "was installed.\n"
        "\n"
        "Each machine keeps `<name>.qcow2` and its own copy of the firmware variables,\n"
        "`<name>-vars.fd`, in `[UserData.VM] vm_dir` (`$HOME/VirtualMachines` by default), so\n"
        "several images can be tried side by side. Memory, processors, disk size and SSH port\n"
        "default to `vm_memory`, `vm_vcpus`, `vm_disk_size` and `vm_ssh_port` in the same\n"
        "section (6144 MB, 4, 60 GB and 2222 when unset). A value given on the command line\n"
        "wins, including `0`.\n"
        "\n"
        "Nothing here needs root or libvirt. The machine gets user-mode networking with the\n"
        "SSH port forwarded, so reach it with `ssh -p 2222 <user>@localhost`."),
    examples = [
        ("Install from an image onto a fresh disk", "boot_vm_image -n llm -i ~/Images/llm.iso"),
        ("Boot what it installed", "boot_vm_image -n llm"),
        ("Install again from scratch", "boot_vm_image -n llm -i ~/Images/llm.iso -r"),
        ("Install with no window, console on this terminal", "boot_vm_image -n llm -i ~/Images/llm.iso -e"),
        ("Install with no window, console to a file", "boot_vm_image -n llm -i ~/Images/llm.iso -e -l ~/llm-console.log"),
        ("Dry run without creating the disk or starting qemu", "boot_vm_image -n llm -i ~/Images/llm.iso -p -v"),
    ],
    notes = [
        "Needs `qemu-system-x86_64`, `qemu-img` and OVMF firmware (the `ovmf` package) on this machine.",
        "Without access to `/dev/kvm` the machine still runs, but an install takes hours; the command warns when it starts.",
        "Installing onto an existing disk without `--reset` installs over it, with a warning.",
        "`--headless` is only useful with an image built with `--serial_console`; otherwise the terminal shows nothing after the boot menu.",
        "The server image unpacks into memory, so 4096 MB is tight.",
        "No GPU is passed through, so driver installs and GPU work are only exercised on real hardware.",
    ],
    see_also = ["build_autoinstall_iso", "testvm"],
    section = "Servers & Machines")
parser.add_group("Machine")
parser.add_string_argument(
    args = ("-n", "--name"),
    default = virtualmachine.DEFAULT_BOOT_NAME,
    description = "Machine name, which names its disk and its firmware variables")
parser.add_string_argument(
    args = ("-i", "--iso"),
    description = "Image to install from; leave it out to boot what was installed")
parser.add_string_argument(
    args = ("-b", "--boot_dir"),
    description = "Directory for the disk and firmware variables, instead of `[UserData.VM] vm_dir`; created if missing")
parser.add_integer_argument(
    args = ("-m", "--memory"),
    description = "Memory in MB; `vm_memory` when omitted")
parser.add_integer_argument(
    args = ("-c", "--vcpus"),
    description = "Processor count; `vm_vcpus` when omitted")
parser.add_integer_argument(
    args = ("-z", "--disk_size"),
    description = "Disk size in GB, used only when the disk is created; `vm_disk_size` when omitted")
parser.add_integer_argument(
    args = ("-t", "--ssh_port"),
    description = "Local port forwarded to the machine's SSH port; `0` gives the machine no network at all; `vm_ssh_port` when omitted")
parser.add_group("Behavior")
parser.add_boolean_argument(
    args = ("-e", "--headless"),
    description = "Open no window, and put the serial console on this terminal")
parser.add_string_argument(
    args = ("-l", "--serial_file"),
    description = "With `--headless`, write the serial console to this file instead of the terminal")
parser.add_boolean_argument(
    args = ("-r", "--reset"),
    description = "Delete the machine's disk and firmware variables first and start from nothing")
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
