# Imports
from joybox import arguments
from joybox import setup
from joybox import system
from joybox import virtualmachine

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "testvm")
    parser.add_string_argument(
        args = ("action",),
        description = "`create`, `destroy`, `snapshot`, `revert`, `snapshots`, `ip`, `console` or `hosts`")
    parser.add_group("Machine")
    parser.add_string_argument(
        args = ("-n", "--name"),
        default = virtualmachine.DEFAULT_NAME,
        description = "Guest name, which also names its disk and seed image")
    parser.add_string_argument(args = ("-s", "--snapshot"), description = "Snapshot name for `snapshot` and `revert`; libvirt picks one, or `revert` uses the current snapshot, when omitted")
    parser.add_group("Action options")
    parser.add_string_argument(args = ("-a", "--address"), default = virtualmachine.DEFAULT_ADDRESS, description = "`create`: address reserved for the guest on the libvirt network")
    parser.add_string_argument(args = ("-k", "--ssh_key"), description = "`create`: SSH public key file to authorise for root; `~/.ssh/id_ed25519.pub` or `id_rsa.pub` when omitted")
    parser.add_string_argument(args = ("-d", "--domain"), default = "joybox.test", description = "`hosts`: domain whose name and configured subdomains point at the guest")
    parser.add_string_argument(args = ("--release",), default = virtualmachine.DEFAULT_RELEASE, description = "`create`: Ubuntu release codename of the cloud image, e.g. `noble`")
    parser.add_integer_argument(args = ("--memory",), default = virtualmachine.DEFAULT_MEMORY, description = "`create`: memory in MB")
    parser.add_integer_argument(args = ("--vcpus",), default = virtualmachine.DEFAULT_VCPUS, description = "`create`: processor count")
    parser.add_integer_argument(args = ("--disk_size",), default = virtualmachine.DEFAULT_DISK_SIZE, description = "`create`: disk size in GB")
    parser.add_boolean_argument(args = ("--remove",), description = "`hosts`: remove the managed block from `/etc/hosts` instead of writing it")
    parser.add_common_arguments()
    return parser

# Create, destroy, snapshot, restore, inspect or attach to the local KVM test guest, or point the test domain at it
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Run the action
    virtualmachine.run_vm_action(
        action = args.action,
        vm_name = args.name,
        snapshot_name = args.snapshot,
        address = args.address,
        ssh_key_file = args.ssh_key,
        domain = args.domain,
        release = args.release,
        memory = args.memory,
        vcpus = args.vcpus,
        disk_size = args.disk_size,
        remove_hosts = args.remove,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
