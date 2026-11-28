# Local test virtual machines.
#
# A rehearsal target for the server stack, so an SSH lockout or a firewall
# change can be tried somewhere disposable first. A real guest rather than a
# container because the things being rehearsed - ufw, a Docker daemon with
# userns-remap, and sshd itself - each need their own kernel-facing stack to
# mean anything.

# Imports
import hashlib
import os
from xml.etree import ElementTree

# Local imports
from joybox import command
from joybox import commandbase
from joybox import runoptions
from joybox import fileops
from joybox import hostsfile
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox.connection import ConnectionLocal

# Tools this needs on the workstation
REQUIRED_TOOLS = ["virt-install", "virsh", "qemu-img", "cloud-localds", "openssl"]

# Where libvirt keeps its images; only root can write here
IMAGE_DIR = "/var/lib/libvirt/images"

# The system libvirt, named explicitly since a non-root virsh defaults to the
# per-user session; membership of the libvirt group grants access
LIBVIRT_URI = "qemu:///system"

# Defaults for a rehearsal guest
DEFAULT_NAME = "joybox-test"
DEFAULT_MEMORY = 4096
DEFAULT_VCPUS = 2
DEFAULT_DISK_SIZE = 20
DEFAULT_RELEASE = "noble"
DEFAULT_OS_VARIANT = "ubuntu22.04"
DEFAULT_NETWORK = "default"

# The address the default guest is reserved, inside libvirt's default network,
# so a server entry can name it once and keep it across rebuilds and reverts
DEFAULT_ADDRESS = "192.168.122.10"

# Public key names looked for when none is given
SSH_KEY_NAMES = ["id_ed25519.pub", "id_rsa.pub"]

###########################################################
# Prerequisites
###########################################################

# Get the tools that are missing from this workstation
def get_missing_tools():
    return [tool for tool in REQUIRED_TOOLS
            if not paths.is_runnable_command(tool)]

# Check the workstation can manage a virtual machine
def are_tools_installed():
    return len(get_missing_tools()) == 0

# Build a virsh command against the system libvirt
def get_virsh_command(arguments):
    return ["virsh", "--connect", LIBVIRT_URI] + list(arguments)

# Get a connection that runs root-only steps through sudo
def get_local_connection(verbose = False, pretend_run = False, exit_on_failure = False):
    return ConnectionLocal(flags = runoptions.RunFlags(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure))

# Find the public key to authorise on a new guest
def resolve_ssh_public_key(key_file = None, home_dir = None):
    if key_file:
        if paths.is_path_file(key_file):
            return key_file
        return None
    home_dir = home_dir or os.path.expanduser("~")
    for name in SSH_KEY_NAMES:
        candidate = paths.join_paths(home_dir, ".ssh", name)
        if paths.is_path_file(candidate):
            return candidate
    return None

# Get a guest's MAC address, fixed per name so its address reservation holds
def get_vm_mac(vm_name = DEFAULT_NAME):
    digest = hashlib.sha256(vm_name.encode()).hexdigest()
    return "52:54:00:%s:%s:%s" % (digest[0:2], digest[2:4], digest[4:6])

###########################################################
# Paths
###########################################################

# Get the backing image for a release
def get_base_image(release = DEFAULT_RELEASE, image_dir = IMAGE_DIR):
    return paths.join_paths(
        image_dir, "%s-server-cloudimg-amd64.img" % release)

# Get the download url for a release
def get_base_image_url(release = DEFAULT_RELEASE):
    return ("https://cloud-images.ubuntu.com/%s/current/"
            "%s-server-cloudimg-amd64.img" % (release, release))

# Get a guest's disk
def get_disk_image(vm_name = DEFAULT_NAME, image_dir = IMAGE_DIR):
    return paths.join_paths(image_dir, "%s.qcow2" % vm_name)

# Get a guest's cloud-init seed
def get_seed_image(vm_name = DEFAULT_NAME, image_dir = IMAGE_DIR):
    return paths.join_paths(image_dir, "%s-seed.iso" % vm_name)

###########################################################
# Cloud-init
###########################################################

# Build the cloud-init user data for a new guest, starting as a fresh server does,
# root by key and no account, so provisioning runs as on the real host; root's console
# password, as a hash, is the way in once hardening closes root login
def build_user_data(vm_name, ssh_public_key, console_password_hash):
    return "\n".join([
        "#cloud-config",
        "hostname: %s" % vm_name,
        "disable_root: false",
        "chpasswd:",
        "  expire: false",
        "  users:",
        "    - name: root",
        "      password: %s" % console_password_hash,
        "      type: hash",
        "ssh_pwauth: true",
        "write_files:",
        "  - path: /root/.ssh/authorized_keys",
        "    owner: root:root",
        "    permissions: '0600'",
        "    defer: true",
        "    content: |",
        "      %s" % ssh_public_key,
        "package_update: true",
        "packages:",
        "  - openssh-server",
        "runcmd:",
        "  - [ systemctl, enable, --now, ssh ]",
        "",
    ])

# Hash a console password the way /etc/shadow keeps it (SHA-512 crypt). The
# password reaches openssl on its input, never its command line.
def hash_console_password(console_password, verbose = False, exit_on_failure = False):
    output = command.run_output_command(
        cmd = ["openssl", "passwd", "-6", "-stdin"],
        options = commandbase.create_command_options(stdin_input = console_password + "\n"),
        verbose = verbose,
        pretend_run = False,
        exit_on_failure = exit_on_failure)
    hashed = (output or "").strip()
    if not hashed.startswith("$6$"):
        logger.log_error("Unable to hash the console password")
        return None
    return hashed

# Build the cloud-init meta data for a new guest
def build_meta_data(vm_name):
    return "\n".join([
        "instance-id: %s" % vm_name,
        "local-hostname: %s" % vm_name,
        "",
    ])

###########################################################
# Guest state
###########################################################

# Check if a guest exists
def does_vm_exist(vm_name = DEFAULT_NAME, verbose = False, pretend_run = False):
    code = command.run_returncode_command(
        cmd = get_virsh_command(["dominfo", vm_name]),
        options = commandbase.create_command_options(suppress_output = True),
        verbose = verbose,
        pretend_run = pretend_run)
    return code == 0

# Get a guest's address, once its lease is up
def get_vm_ip(vm_name = DEFAULT_NAME, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = get_virsh_command(["domifaddr", vm_name]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    return parse_vm_ip(output)

# Read an address out of virsh domifaddr output
def parse_vm_ip(output):
    if not output:
        return None
    for line in output.splitlines():
        if "ipv4" not in line:
            continue
        for token in line.split():
            if "/" in token and token.count(".") == 3:
                return token.split("/")[0]
    return None

###########################################################
# Lifecycle
###########################################################

# Download the backing image for a release if it is not already here
def fetch_base_image(
    release = DEFAULT_RELEASE,
    image_dir = IMAGE_DIR,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get base image
    base_image = get_base_image(release, image_dir)
    if paths.is_path_file(base_image):
        return base_image

    # Create image dir
    connection = get_local_connection(verbose, pretend_run, exit_on_failure)
    if not connection.make_directory(image_dir, sudo = True):
        return None

    # Download image
    logger.log_info("Downloading the %s cloud image" % release)
    code = connection.run_return_code(
        cmd = [
            "curl", "-fL",
            "--proto", "=https",
            "--tlsv1.2",
            "-o", base_image,
            get_base_image_url(release)
        ],
        sudo = True)
    if code != 0:
        return None
    return base_image

# Build the command that creates a guest's disk from the backing image
def get_create_disk_command(base_image, disk_image, disk_size = DEFAULT_DISK_SIZE):
    return [
        "qemu-img", "create",
        "-f", "qcow2",
        "-F", "qcow2",
        "-b", base_image,
        disk_image,
        "%dG" % int(disk_size)
    ]

# Build the command that installs a guest
def get_install_command(
    vm_name,
    disk_image,
    seed_image,
    memory = DEFAULT_MEMORY,
    vcpus = DEFAULT_VCPUS,
    os_variant = DEFAULT_OS_VARIANT,
    network = DEFAULT_NETWORK,
    mac = None):
    network_option = "network=%s,model=virtio" % network
    if mac:
        network_option += ",mac=%s" % mac
    return [
        "virt-install",
        "--connect", LIBVIRT_URI,
        "--name", vm_name,
        "--memory", str(memory),
        "--vcpus", str(vcpus),
        "--disk", "path=%s,device=disk,bus=virtio" % disk_image,
        "--disk", "path=%s,device=cdrom" % seed_image,
        "--os-variant", os_variant,
        "--network", network_option,
        "--graphics", "none",
        "--import",
        "--noautoconsole"
    ]

# Read whether virsh net-info reports a network as running
# Persistent and Autostart also answer yes, so only the Active line counts.
def is_network_active(output):
    if not output:
        return False
    for line in output.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "active":
            return value.strip().lower() == "yes"
    return False

# Make sure libvirt's network is up, so a new guest gets a lease
def start_network(network = DEFAULT_NETWORK, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = get_virsh_command(["net-info", network]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    if is_network_active(output):
        return True
    for arguments in [["net-start", network], ["net-autostart", network]]:
        command.run_returncode_command(
            cmd = get_virsh_command(arguments),
            verbose = verbose,
            pretend_run = pretend_run)
    return True

# Read the fixed-address entries of a network's DHCP config
# The dns section has host elements of its own, which are not reservations.
def parse_dhcp_hosts(network_xml):
    if not network_xml:
        return []
    try:
        root = ElementTree.fromstring(network_xml)
    except ElementTree.ParseError:
        return []
    return [
        {key: host.get(key) for key in ["mac", "name", "ip"] if host.get(key)}
        for dhcp in root.iter("dhcp")
        for host in dhcp.iter("host")
        if host.get("mac") or host.get("ip")]

# Build the XML for one fixed-address entry
def build_dhcp_host_xml(mac = None, name = None, ip = None):
    attributes = [("mac", mac), ("name", name), ("ip", ip)]
    return "<host %s/>" % " ".join(
        "%s='%s'" % (key, value) for key, value in attributes if value)

# Get the entries that would conflict with a reservation: the same guest, the
# same MAC, or the same address held by something else
def get_conflicting_dhcp_hosts(hosts, vm_name, mac, address):
    return [host for host in hosts
            if host.get("mac") == mac or host.get("ip") == address or host.get("name") == vm_name]

# Build the command that changes a network's DHCP entries, live and persisted
def get_dhcp_update_command(network, operation, host_xml):
    return get_virsh_command([
        "net-update", network, operation, "ip-dhcp-host", host_xml, "--live", "--config"])

# Reserve an address for a guest's MAC, replacing whatever held either before
def reserve_address(
    vm_name,
    address,
    mac = None,
    network = DEFAULT_NETWORK,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    mac = mac or get_vm_mac(vm_name)
    output = command.run_output_command(
        cmd = get_virsh_command(["net-dumpxml", network]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    hosts = parse_dhcp_hosts(output)
    wanted = {"mac": mac, "name": vm_name, "ip": address}
    if wanted in hosts:
        return True
    for host in get_conflicting_dhcp_hosts(hosts, vm_name, mac, address):
        command.run_returncode_command(
            cmd = get_dhcp_update_command(network, "delete", build_dhcp_host_xml(**host)),
            verbose = verbose,
            pretend_run = pretend_run)
    code = command.run_returncode_command(
        cmd = get_dhcp_update_command(network, "add-last", build_dhcp_host_xml(**wanted)),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to reserve %s for %s" % (address, vm_name))
        return False
    return True

# Forget a rebuilt guest's old host key, so ssh does not refuse the new one
def forget_host_key(address, verbose = False, pretend_run = False):
    command.run_returncode_command(
        cmd = ["ssh-keygen", "-R", address],
        options = commandbase.create_command_options(suppress_output = True),
        verbose = verbose,
        pretend_run = pretend_run)

# Create a guest
def create_vm(
    vm_name = DEFAULT_NAME,
    ssh_key_file = None,
    address = DEFAULT_ADDRESS,
    memory = DEFAULT_MEMORY,
    vcpus = DEFAULT_VCPUS,
    disk_size = DEFAULT_DISK_SIZE,
    release = DEFAULT_RELEASE,
    console_password = "joybox",
    image_dir = IMAGE_DIR,
    network = DEFAULT_NETWORK,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check prerequisites
    if not can_create_vm(vm_name, verbose, pretend_run):
        return False

    # Create the guest's disk and cloud-init seed
    disk_image, seed_image = _create_vm_images(
        vm_name, ssh_key_file, console_password, release, image_dir, disk_size, verbose, pretend_run, exit_on_failure)
    if not seed_image:
        return False

    # Bring up the network, pin the guest's address, and install
    return _install_vm(
        vm_name, address, network, disk_image, seed_image, memory, vcpus, verbose, pretend_run, exit_on_failure)

# Read what the guest will trust, then create its disk on top of the backing image and its
# cloud-init seed; (disk image, seed image), or (None, None) when a step fails
def _create_vm_images(vm_name, ssh_key_file, console_password, release, image_dir, disk_size, verbose, pretend_run, exit_on_failure):

    # Read what the guest will trust
    ssh_public_key, console_password_hash = _read_guest_credentials(ssh_key_file, console_password, verbose, exit_on_failure)
    if not ssh_public_key:
        return None, None

    # Create the guest's own disk on top of the backing image
    connection, disk_image = _create_vm_disk(vm_name, release, image_dir, disk_size, verbose, pretend_run, exit_on_failure)
    if not disk_image:
        return None, None

    # Build the cloud-init seed
    seed_image = _build_seed_image(
        connection, vm_name, image_dir, ssh_public_key, console_password_hash, verbose, pretend_run, exit_on_failure)
    if not seed_image:
        return None, None
    return disk_image, seed_image

# Fetch the release's backing image and create the guest's disk on top of it
# Returns the local connection and the disk image, or (None, None) on failure
def _create_vm_disk(vm_name, release, image_dir, disk_size, verbose, pretend_run, exit_on_failure):

    # Get the backing image
    base_image = fetch_base_image(
        release = release,
        image_dir = image_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not base_image:
        return None, None

    # Create the guest's own disk on top of it
    connection = get_local_connection(verbose, pretend_run, exit_on_failure)
    disk_image = get_disk_image(vm_name, image_dir)
    code = connection.run_return_code(
        cmd = get_create_disk_command(base_image, disk_image, disk_size),
        sudo = True)
    if code != 0:
        return None, None
    return connection, disk_image

# Whether the host has every tool and no guest is already named vm_name, logging what is wrong
def can_create_vm(vm_name, verbose = False, pretend_run = False):

    # Check prerequisites
    missing = get_missing_tools()
    if missing:
        logger.log_error("Missing tools: %s" % ", ".join(missing))
        logger.log_error(
            "Install them with: python3 bootstrap.py -a setup "
            "-t local_ubuntu --components aptget")
        return False

    # Refuse to build over an existing guest
    if does_vm_exist(vm_name, verbose = verbose, pretend_run = pretend_run):
        logger.log_error("A virtual machine named '%s' already exists" % vm_name)
        return False
    return True

# The SSH public key to authorise and the console password hash; (None, None) when either is unavailable
def _read_guest_credentials(ssh_key_file, console_password, verbose, exit_on_failure):

    # Find the key to authorise
    ssh_public_key_file = resolve_ssh_public_key(ssh_key_file)
    if not ssh_public_key_file:
        logger.log_error("No SSH public key found")
        logger.log_error("Generate one with: ssh-keygen -t ed25519")
        return None, None
    ssh_public_key = serialization.read_text_file(
        src = ssh_public_key_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not ssh_public_key:
        return None, None
    ssh_public_key = ssh_public_key.strip()
    console_password_hash = hash_console_password(console_password, verbose = verbose, exit_on_failure = exit_on_failure)
    if not console_password_hash:
        return None, None
    return ssh_public_key, console_password_hash

# Write the cloud-init user-data and meta-data into seed_dir; their paths, or None when one cannot be written
def _write_seed_files(seed_dir, vm_name, ssh_public_key, console_password_hash, verbose, pretend_run, exit_on_failure):
    seed_files = []
    for name, contents in [
        ("user-data", build_user_data(vm_name, ssh_public_key, console_password_hash)),
        ("meta-data", build_meta_data(vm_name))]:
        seed_file = paths.join_paths(seed_dir, name)
        success = fileops.touch_file(
            src = seed_file,
            contents = contents,
            private = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None
        seed_files.append(seed_file)
    return seed_files

# Write the cloud-init user and meta data and pack them into the guest's seed image; its path, or None
def _build_seed_image(connection, vm_name, image_dir, ssh_public_key, console_password_hash, verbose, pretend_run, exit_on_failure):
    seed_image = get_seed_image(vm_name, image_dir)
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as seed_dir:
        if not seed_dir:
            return None
        seed_files = _write_seed_files(seed_dir, vm_name, ssh_public_key, console_password_hash, verbose, pretend_run, exit_on_failure)
        if not seed_files:
            return None
        code = connection.run_return_code(
            cmd = ["cloud-localds", seed_image, *seed_files],
            sudo = True)
        if code != 0:
            return None
    return seed_image

# Start the network, reserve the guest's address when one is given, and run the install; whether it succeeded
def _install_vm(vm_name, address, network, disk_image, seed_image, memory, vcpus, verbose, pretend_run, exit_on_failure):
    start_network(network, verbose = verbose, pretend_run = pretend_run)
    mac = get_vm_mac(vm_name)
    if address:
        success = reserve_address(
            vm_name = vm_name,
            address = address,
            mac = mac,
            network = network,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        forget_host_key(address, verbose = verbose, pretend_run = pretend_run)
    code = command.run_returncode_command(
        cmd = get_install_command(
            vm_name = vm_name,
            disk_image = disk_image,
            seed_image = seed_image,
            memory = memory,
            vcpus = vcpus,
            network = network,
            mac = mac),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Start a guest that exists but is shut off; a running one is left alone
def start_vm(vm_name = DEFAULT_NAME, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = get_virsh_command(["domstate", vm_name]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    if output and "running" in output:
        return True
    code = command.run_returncode_command(
        cmd = get_virsh_command(["start", vm_name]),
        verbose = verbose,
        pretend_run = pretend_run)
    return code == 0

# Read the MAC a guest's network interface actually has
def parse_interface_mac(output):
    if not output:
        return None
    for line in output.splitlines():
        for token in line.split():
            if token.count(":") == 5:
                return token.lower()
    return None

# MAC of the guest's first network interface from virsh domiflist; None when none is listed
def get_vm_interface_mac(vm_name = DEFAULT_NAME, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = get_virsh_command(["domiflist", vm_name]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    return parse_interface_mac(output)

# Remove a snapshot, so one with the same name can be taken again
def delete_snapshot(vm_name = DEFAULT_NAME, snapshot_name = None, verbose = False, pretend_run = False):
    if snapshot_name not in list_snapshots(vm_name, verbose = verbose, pretend_run = pretend_run):
        return True
    code = command.run_returncode_command(
        cmd = get_virsh_command(["snapshot-delete", vm_name, snapshot_name]),
        verbose = verbose,
        pretend_run = pretend_run)
    return code == 0

# Take a snapshot, so a risky step can be undone
def snapshot_vm(
    vm_name = DEFAULT_NAME,
    snapshot_name = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    cmd = get_virsh_command(["snapshot-create-as", vm_name])
    if snapshot_name:
        cmd += [snapshot_name]
    code = command.run_returncode_command(
        cmd = cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Go back to a snapshot
def revert_vm(
    vm_name = DEFAULT_NAME,
    snapshot_name = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    cmd = get_virsh_command(["snapshot-revert", vm_name])
    if snapshot_name:
        cmd += [snapshot_name]
    else:
        cmd += ["--current"]
    code = command.run_returncode_command(
        cmd = cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# List a guest's snapshots
def list_snapshots(vm_name = DEFAULT_NAME, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = get_virsh_command(["snapshot-list", vm_name, "--name"]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]

# Destroy a guest and everything belonging to it
def destroy_vm(
    vm_name = DEFAULT_NAME,
    image_dir = IMAGE_DIR,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if it exists
    if not does_vm_exist(vm_name, verbose = verbose, pretend_run = pretend_run):
        logger.log_info("No virtual machine named '%s'" % vm_name)
        return True

    # Stop it first; a running guest cannot be undefined
    command.run_returncode_command(
        cmd = get_virsh_command(["destroy", vm_name]),
        options = commandbase.create_command_options(suppress_output = True),
        verbose = verbose,
        pretend_run = pretend_run)
    code = command.run_returncode_command(
        cmd = get_virsh_command(["undefine", vm_name, "--remove-all-storage", "--snapshots-metadata"]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # The seed is not attached storage, so it outlives the undefine
    connection = get_local_connection(verbose, pretend_run, exit_on_failure = False)
    return connection.remove_file_or_directory(get_seed_image(vm_name, image_dir), sudo = True)

# Attach to a guest's serial console, the way back in after an ssh lockout
def get_console_command(vm_name = DEFAULT_NAME):
    return get_virsh_command(["console", vm_name])

###########################################################
# Test machine actions
###########################################################

# Create a guest of the given memory, processors, disk size and release, logging where
# it boots; quits when it cannot be created
def _create_test_vm(vm_name, ssh_key_file, address, memory, vcpus, disk_size, release, flags):
    success = create_vm(
        vm_name = vm_name,
        ssh_key_file = ssh_key_file,
        address = address,
        memory = memory,
        vcpus = vcpus,
        disk_size = disk_size,
        release = release,
        **flags)
    if not success:
        logger.log_error("Unable to create the virtual machine", quit_program = True)
    logger.log_info("Booting at %s; first boot takes a minute or two" % address)

# Log a guest's snapshots, one per line
def _log_test_vm_snapshots(vm_name, verbose):
    for snapshot in list_snapshots(vm_name, verbose = verbose):
        logger.log_info(snapshot)

# A guest's address; quits when it has none yet
def _get_test_vm_address(vm_name, verbose):
    address = get_vm_ip(vm_name, verbose = verbose)
    if not address:
        logger.log_error("No address yet for '%s'" % vm_name, quit_program = True)
    return address

# Point a domain and its configured subdomains at a guest in /etc/hosts, or drop the
# managed block when remove is set; quits when the guest has no address yet
def _update_test_hosts(vm_name, domain, remove, verbose, pretend_run, exit_on_failure):
    if remove:
        hostsfile.remove_entries(
            sudo = True,
            verbose = True,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return
    hostsfile.set_entries(
        address = _get_test_vm_address(vm_name, verbose),
        domain = domain,
        sudo = True,
        verbose = True,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Call the handler for action from handlers; quits when there is none
def _dispatch_vm_action(action, handlers):
    handler = handlers.get(action)
    if handler:
        handler()
    else:
        logger.log_error("Unknown action '%s'" % action, quit_program = True)

# Run a testvm action on a guest: create, destroy, snapshot, revert, snapshots (logged one
# per line), ip (written to stdout), console or hosts; quits on any other action
def run_vm_action(
    action,
    vm_name = DEFAULT_NAME,
    snapshot_name = None,
    address = DEFAULT_ADDRESS,
    ssh_key_file = None,
    domain = None,
    release = DEFAULT_RELEASE,
    memory = DEFAULT_MEMORY,
    vcpus = DEFAULT_VCPUS,
    disk_size = DEFAULT_DISK_SIZE,
    remove_hosts = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    flags = {"verbose": verbose, "pretend_run": pretend_run, "exit_on_failure": exit_on_failure}
    _dispatch_vm_action(action, {
        "create": lambda: _create_test_vm(vm_name, ssh_key_file, address, memory, vcpus, disk_size, release, flags),
        "destroy": lambda: destroy_vm(vm_name = vm_name, **flags),
        "snapshot": lambda: snapshot_vm(vm_name = vm_name, snapshot_name = snapshot_name, **flags),
        "revert": lambda: revert_vm(vm_name = vm_name, snapshot_name = snapshot_name, **flags),
        "snapshots": lambda: _log_test_vm_snapshots(vm_name, verbose),
        "ip": lambda: logger.log_output("%s\n" % _get_test_vm_address(vm_name, verbose)),
        "console": lambda: command.run_interactive_command(cmd = get_console_command(vm_name), **flags),
        "hosts": lambda: _update_test_hosts(vm_name, domain, remove_hosts, verbose, pretend_run, exit_on_failure),
    })
