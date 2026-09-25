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
parser = arguments.ArgumentParser(
    description = "Manage the local KVM virtual machine used to rehearse server changes.",
    details = (
        "Builds and manages a throwaway Ubuntu Server guest under libvirt, so a server change\n"
        "such as the SSH lockout or a firewall rule can be proven before it touches a real\n"
        "server. The guest is treated as just another `[UserData.Servers]` entry: point\n"
        "`server_<n>_host` at its address, with `server_<n>_domain_name` and\n"
        "`server_<n>_tls_mode = mkcert`, and the same bootstrap installers run against it as\n"
        "against a real host.\n"
        "\n"
        "Actions:\n"
        "\n"
        "- `create`: download the Ubuntu cloud image for `--release` into\n"
        "  `/var/lib/libvirt/images` (once), make the guest's own disk on top of it, and boot\n"
        "  it on libvirt's `default` NAT network. cloud-init creates the account with\n"
        "  passwordless sudo and your SSH public key, plus the console password `joybox`.\n"
        "  Refuses if a guest with that name already exists.\n"
        "- `ip`: print the guest's address once it has a lease.\n"
        "- `hosts`: write a marked block into `/etc/hosts` pointing `--domain` and every\n"
        "  subdomain configured in `~/JoyBox.ini` (each `*_subdomain` setting) at the guest.\n"
        "  With `--remove` it takes the block out again. Re-run it after a revert if the\n"
        "  address changed.\n"
        "- `snapshot` / `revert`: take a snapshot, or go back to one; `revert` without\n"
        "  `--snapshot` goes back to the current one. `snapshots` lists them.\n"
        "- `console`: attach to the serial console, the way back in when SSH is broken. Log\n"
        "  in with the console password; leave with Ctrl+].\n"
        "- `destroy`: stop the guest and delete it with its disk, seed and snapshots."),
    examples = [
        ("Create the guest for your own account", "testvm create --username \"$USER\""),
        ("Create a larger guest with a specific key", "testvm create -u alice -k ~/.ssh/id_ed25519.pub --memory 8192 --vcpus 4 --disk_size 40"),
        ("Print its address", "testvm ip"),
        ("Point joybox.test and its subdomains at it", "testvm hosts"),
        ("Snapshot before a risky step", "testvm snapshot --snapshot pre-sshd"),
        ("Go back to that snapshot", "testvm revert --snapshot pre-sshd"),
        ("Get in through the serial console", "testvm console"),
        ("Take the test domain out of /etc/hosts", "testvm hosts --remove"),
        ("Delete the guest with its disk and snapshots", "testvm destroy"),
        ("Dry run of destroy, changing nothing", "testvm destroy -p -v"),
    ],
    notes = [
        "Run it as root (with sudo): it talks to the system libvirt, writes guest images under `/var/lib/libvirt/images`, and edits `/etc/hosts`.",
        "Needs `virt-install`, `virsh`, `qemu-img` and `cloud-localds`; `python3 bootstrap.py -a setup -t local_ubuntu --components aptget` installs them.",
        "Without `--ssh_key`, `create` uses `~/.ssh/id_ed25519.pub` or `~/.ssh/id_rsa.pub` of the account (under `/home`). Without `--username`, the account is the one that ran sudo.",
        "Take a snapshot before anything you would not want to repeat by hand; a revert takes seconds, a rebuild much longer.",
        "The guest defaults to 2 processors, 4 GB and 20 GB, close to a Hetzner CX22. It has no sshfs Storage Box, no real DNS or ACME, and no public address.",
    ],
    see_also = ["verify_server", "boot_vm_image"],
    section = "Servers & Machines")
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
parser.add_string_argument(args = ("-u", "--username"), description = "`create`: account to make in the guest; the user who ran sudo when omitted")
parser.add_string_argument(args = ("-k", "--ssh_key"), description = "`create`: SSH public key file to authorise; the account's `~/.ssh/id_ed25519.pub` or `id_rsa.pub` when omitted")
parser.add_string_argument(args = ("-d", "--domain"), default = "joybox.test", description = "`hosts`: domain whose name and configured subdomains point at the guest")
parser.add_string_argument(args = ("--release"), default = virtualmachine.DEFAULT_RELEASE, description = "`create`: Ubuntu release codename of the cloud image, e.g. `noble`")
parser.add_integer_argument(args = ("--memory"), default = virtualmachine.DEFAULT_MEMORY, description = "`create`: memory in MB")
parser.add_integer_argument(args = ("--vcpus"), default = virtualmachine.DEFAULT_VCPUS, description = "`create`: processor count")
parser.add_integer_argument(args = ("--disk_size"), default = virtualmachine.DEFAULT_DISK_SIZE, description = "`create`: disk size in GB")
parser.add_boolean_argument(args = ("--remove"), description = "`hosts`: remove the managed block from `/etc/hosts` instead of writing it")
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
