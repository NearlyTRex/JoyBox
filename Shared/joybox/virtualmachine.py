# Local test virtual machines.
#
# A rehearsal target for the server stack, so an SSH lockout or a firewall
# change can be tried somewhere disposable first. A real guest rather than a
# container because the things being rehearsed - ufw, a Docker daemon with
# userns-remap, and sshd itself - each need their own kernel-facing stack to
# mean anything.

# Imports
import os

# Local imports
import joybox.command as command
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.paths as paths
import joybox.serialization as serialization

# Tools this needs on the workstation
REQUIRED_TOOLS = ["virt-install", "virsh", "qemu-img", "cloud-localds"]

# Where libvirt keeps its images
IMAGE_DIR = "/var/lib/libvirt/images"

# Defaults for a rehearsal guest
DEFAULT_NAME = "joybox-test"
DEFAULT_MEMORY = 4096
DEFAULT_VCPUS = 2
DEFAULT_DISK_SIZE = 20
DEFAULT_RELEASE = "noble"
DEFAULT_OS_VARIANT = "ubuntu22.04"
DEFAULT_NETWORK = "default"

# Public key names looked for when none is given
SSH_KEY_NAMES = ["id_ed25519.pub", "id_rsa.pub"]

###########################################################
# Prerequisites
###########################################################

# Get the tools that are missing from this workstation
def get_missing_tools():
    return [tool for tool in REQUIRED_TOOLS
            if not command.is_runnable_command(tool)]

# Check the workstation can manage a virtual machine
def are_tools_installed():
    return len(get_missing_tools()) == 0

# Find the public key to authorise on a new guest
def resolve_ssh_public_key(username, key_file = None):
    if key_file:
        if paths.is_path_file(key_file):
            return key_file
        return None
    for name in SSH_KEY_NAMES:
        candidate = paths.join_paths(
            paths.join_paths("/home", username), ".ssh", name)
        if paths.is_path_file(candidate):
            return candidate
    return None

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

# Build the cloud-init user data for a new guest.
# A console password alongside the key is deliberate: the sshd hardening step
# is one of the things being rehearsed, and locking the key out would
# otherwise leave no way back in.
def build_user_data(vm_name, username, ssh_public_key, console_password = "joybox"):
    return "\n".join([
        "#cloud-config",
        "hostname: %s" % vm_name,
        "users:",
        "  - name: %s" % username,
        "    groups: [sudo]",
        "    shell: /bin/bash",
        "    sudo: \"ALL=(ALL) NOPASSWD:ALL\"",
        "    lock_passwd: false",
        "    ssh_authorized_keys:",
        "      - %s" % ssh_public_key,
        "chpasswd:",
        "  list: |",
        "    %s:%s" % (username, console_password),
        "  expire: false",
        "ssh_pwauth: true",
        "package_update: true",
        "packages:",
        "  - openssh-server",
        "runcmd:",
        "  - [ systemctl, enable, --now, ssh ]",
        "",
    ])

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
        cmd = ["virsh", "dominfo", vm_name],
        options = command.create_command_options(suppress_output = True),
        verbose = verbose,
        pretend_run = pretend_run)
    return code == 0

# Get a guest's address, once its lease is up
def get_vm_ip(vm_name = DEFAULT_NAME, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = ["virsh", "domifaddr", vm_name],
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
    success = fileops.make_directory(
        src = image_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return None

    # Download image
    logger.log_info("Downloading the %s cloud image" % release)
    code = command.run_returncode_command(
        cmd = [
            "curl", "-fL",
            "--proto", "=https",
            "--tlsv1.2",
            "-o", base_image,
            get_base_image_url(release)
        ],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
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
    network = DEFAULT_NETWORK):
    return [
        "virt-install",
        "--name", vm_name,
        "--memory", str(memory),
        "--vcpus", str(vcpus),
        "--disk", "path=%s,device=disk,bus=virtio" % disk_image,
        "--disk", "path=%s,device=cdrom" % seed_image,
        "--os-variant", os_variant,
        "--network", "network=%s,model=virtio" % network,
        "--graphics", "none",
        "--import",
        "--noautoconsole"
    ]

# Make sure libvirt's network is up, so a new guest gets a lease
def start_network(network = DEFAULT_NETWORK, verbose = False, pretend_run = False):
    output = command.run_output_command(
        cmd = ["virsh", "net-info", network],
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    if output and "yes" in output.lower():
        return True
    for arguments in [["net-start", network], ["net-autostart", network]]:
        command.run_returncode_command(
            cmd = ["virsh"] + arguments,
            verbose = verbose,
            pretend_run = pretend_run)
    return True

# Create a guest
def create_vm(
    vm_name = DEFAULT_NAME,
    username = None,
    ssh_key_file = None,
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

    # Find the key to authorise
    if not username:
        username = os.environ.get("SUDO_USER") or os.environ.get("USER")
    ssh_public_key_file = resolve_ssh_public_key(username, ssh_key_file)
    if not ssh_public_key_file:
        logger.log_error("No SSH public key found for %s" % username)
        logger.log_error("Generate one with: ssh-keygen -t ed25519")
        return False
    ssh_public_key = serialization.read_text_file(
        src = ssh_public_key_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not ssh_public_key:
        return False
    ssh_public_key = ssh_public_key.strip()

    # Get the backing image
    base_image = fetch_base_image(
        release = release,
        image_dir = image_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not base_image:
        return False

    # Create the guest's own disk on top of it
    disk_image = get_disk_image(vm_name, image_dir)
    code = command.run_returncode_command(
        cmd = get_create_disk_command(base_image, disk_image, disk_size),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Build the cloud-init seed
    seed_success, seed_dir = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not seed_success:
        return False
    seed_image = get_seed_image(vm_name, image_dir)
    try:
        user_data = paths.join_paths(seed_dir, "user-data")
        meta_data = paths.join_paths(seed_dir, "meta-data")
        fileops.touch_file(
            src = user_data,
            contents = build_user_data(
                vm_name, username, ssh_public_key, console_password),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        fileops.touch_file(
            src = meta_data,
            contents = build_meta_data(vm_name),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        code = command.run_returncode_command(
            cmd = ["cloud-localds", seed_image, user_data, meta_data],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False
    finally:
        fileops.remove_directory(
            src = seed_dir,
            verbose = verbose,
            pretend_run = pretend_run)

    # Bring up the network and install
    start_network(network, verbose = verbose, pretend_run = pretend_run)
    code = command.run_returncode_command(
        cmd = get_install_command(
            vm_name = vm_name,
            disk_image = disk_image,
            seed_image = seed_image,
            memory = memory,
            vcpus = vcpus,
            network = network),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Take a snapshot, so a risky step can be undone
def snapshot_vm(
    vm_name = DEFAULT_NAME,
    snapshot_name = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    cmd = ["virsh", "snapshot-create-as", vm_name]
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
    cmd = ["virsh", "snapshot-revert", vm_name]
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
        cmd = ["virsh", "snapshot-list", vm_name, "--name"],
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
        cmd = ["virsh", "destroy", vm_name],
        options = command.create_command_options(suppress_output = True),
        verbose = verbose,
        pretend_run = pretend_run)
    code = command.run_returncode_command(
        cmd = ["virsh", "undefine", vm_name, "--remove-all-storage", "--snapshots-metadata"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # The seed is not attached storage, so it outlives the undefine
    fileops.remove_file(
        src = get_seed_image(vm_name, image_dir),
        verbose = verbose,
        pretend_run = pretend_run)
    return True

# Attach to a guest's serial console, the way back in after an ssh lockout
def get_console_command(vm_name = DEFAULT_NAME):
    return ["virsh", "console", vm_name]
