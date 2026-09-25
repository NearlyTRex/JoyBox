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
import joybox.runoptions as runoptions
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.paths as paths
import joybox.serialization as serialization
import joybox.settings as settings
from joybox.connection import ConnectionLocal

# Tools this needs on the workstation
REQUIRED_TOOLS = ["virt-install", "virsh", "qemu-img", "cloud-localds"]

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
        cmd = get_virsh_command(["dominfo", vm_name]),
        options = command.create_command_options(suppress_output = True),
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
    network = DEFAULT_NETWORK):
    return [
        "virt-install",
        "--connect", LIBVIRT_URI,
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
        cmd = get_virsh_command(["net-info", network]),
        verbose = verbose,
        pretend_run = pretend_run)
    if isinstance(output, bytes):
        output = output.decode()
    if output and "yes" in output.lower():
        return True
    for arguments in [["net-start", network], ["net-autostart", network]]:
        command.run_returncode_command(
            cmd = get_virsh_command(arguments),
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
        username = os.environ.get("USER")
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
    connection = get_local_connection(verbose, pretend_run, exit_on_failure)
    disk_image = get_disk_image(vm_name, image_dir)
    code = connection.run_return_code(
        cmd = get_create_disk_command(base_image, disk_image, disk_size),
        sudo = True)
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
        code = connection.run_return_code(
            cmd = ["cloud-localds", seed_image, user_data, meta_data],
            sudo = True)
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
        options = command.create_command_options(suppress_output = True),
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
# Booting an image directly
#
# The guest above starts from a cloud image that is already installed.
# Testing an installer image is the other way round: a blank disk, the image
# in the drive, and firmware that boots it the way the target machine will.
# That is qemu on its own, since nothing here needs to outlive the test and
# nothing needs libvirt to manage it.
###########################################################

# Tools a direct boot needs
BOOT_TOOLS = ["qemu-system-x86_64", "qemu-img"]

# Defaults for a machine booted from an image
DEFAULT_BOOT_NAME = "joybox-boot"
DEFAULT_BOOT_MEMORY = 6144
DEFAULT_BOOT_VCPUS = 4
DEFAULT_BOOT_DISK_SIZE = 60
DEFAULT_SSH_PORT = 2222

# Where a booted machine keeps its disk and its copy of the firmware, when
# the configuration does not say
DEFAULT_BOOT_DIR = "$HOME/VirtualMachines"

# Firmware pairs, as distributions lay them out. Booting an installer image
# the way the target machine will means uefi, and uefi means supplying the
# firmware, since the built-in bios cannot boot an efi system partition.
FIRMWARE_PAIRS = [
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    ("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd", "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"),
    ("/usr/share/qemu/ovmf-x86_64-code.bin", "/usr/share/qemu/ovmf-x86_64-vars.bin"),
]

# Get the tools a direct boot is missing from this workstation
def get_missing_boot_tools():
    return [tool for tool in BOOT_TOOLS if not command.is_runnable_command(tool)]

# Find a firmware pair this workstation has
def get_firmware_pair(pairs = None):
    for code_file, vars_file in (pairs if pairs is not None else FIRMWARE_PAIRS):
        if paths.is_path_file(code_file) and paths.is_path_file(vars_file):
            return code_file, vars_file
    return None

# Determine whether the processor can be handed straight through
# Without it a guest still runs, slowly enough that an install is a wait
# rather than a test.
def is_acceleration_available():
    return os.access("/dev/kvm", os.R_OK | os.W_OK)

# Get where booted machines are kept
# Not beside the libvirt guests, which live somewhere only root can write;
# nothing here needs privileges.
def get_boot_dir(boot_dir = None):
    if boot_dir:
        return boot_dir
    return settings.get_path_value(
        "UserData.VM", "vm_dir", DEFAULT_BOOT_DIR, throw_exception = False)

# Get a booted machine's disk
def get_boot_disk(vm_name = DEFAULT_BOOT_NAME, boot_dir = None):
    return paths.join_paths(get_boot_dir(boot_dir), "%s.qcow2" % vm_name)

# Get a booted machine's own copy of the firmware variables
# The firmware writes its boot entries here, so the distribution's copy is
# left alone and each machine gets one of its own.
def get_boot_firmware_vars(vm_name = DEFAULT_BOOT_NAME, boot_dir = None):
    return paths.join_paths(get_boot_dir(boot_dir), "%s-vars.fd" % vm_name)

# Get a numeric setting for a booted machine
# A value given on the command line wins; zero is a real answer, so only an
# absent one falls back to the configuration.
def get_boot_setting(field, fallback, given = None):
    if given is not None:
        return given
    return settings.get_integer_value(
        "UserData.VM", field, fallback, throw_exception = False)

# Build the command that makes a blank disk
def get_create_boot_disk_command(disk_image, disk_size = DEFAULT_BOOT_DISK_SIZE):
    return ["qemu-img", "create", "-f", "qcow2", disk_image, "%dG" % disk_size]

# Build the command that boots a machine
# An image in the drive means an install, so the machine is pointed at the
# drive and stopped when the installer reboots. Without one the disk is
# booted, which is how the installed system is looked at afterwards.
def get_boot_command(
    disk_image,
    firmware_code,
    firmware_vars,
    iso_file = None,
    memory = DEFAULT_BOOT_MEMORY,
    vcpus = DEFAULT_BOOT_VCPUS,
    ssh_port = DEFAULT_SSH_PORT,
    headless = False,
    serial_file = None,
    accelerated = True):
    machine = "q35,accel=kvm" if accelerated else "q35"
    boot_cmd = ["qemu-system-x86_64", "-machine", machine]
    if accelerated:
        boot_cmd += ["-cpu", "host"]
    boot_cmd += [
        "-m", "%dM" % memory,
        "-smp", str(vcpus),
        "-drive", "if=pflash,format=raw,readonly=on,file=%s" % firmware_code,
        "-drive", "if=pflash,format=raw,file=%s" % firmware_vars,
        "-drive", "file=%s,if=virtio" % disk_image,
    ]
    if iso_file:

        # Stopping at the reboot matters: the image is still in the drive,
        # and firmware that boots it again starts the install over.
        boot_cmd += [
            "-drive", "file=%s,media=cdrom,readonly=on" % iso_file,
            "-boot", "d",
            "-no-reboot",
        ]
    if ssh_port:
        boot_cmd += [
            "-netdev", "user,id=net0,hostfwd=tcp::%d-:22" % ssh_port,
            "-device", "virtio-net,netdev=net0",
        ]
    else:
        boot_cmd += ["-net", "none"]
    if headless:
        boot_cmd += ["-display", "none"]
        boot_cmd += ["-serial", "file:%s" % serial_file] if serial_file else ["-serial", "mon:stdio"]
    return boot_cmd

# Make a blank disk for a machine to install onto
def create_boot_disk(
    disk_image,
    disk_size = DEFAULT_BOOT_DISK_SIZE,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    code = command.run_returncode_command(
        cmd = get_create_boot_disk_command(disk_image, disk_size),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to create disk %s" % disk_image)
        return False
    return True

# Give a machine its own copy of the firmware variables
def prepare_boot_firmware(
    firmware_vars,
    template_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if paths.is_path_file(firmware_vars):
        return True
    return fileops.copy_file_or_directory(
        src = template_file,
        dest = firmware_vars,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Boot a machine, installing from an image when one is given
def boot_vm_image(
    vm_name = DEFAULT_BOOT_NAME,
    iso_file = None,
    boot_dir = None,
    disk_size = None,
    memory = None,
    vcpus = None,
    ssh_port = None,
    headless = False,
    serial_file = None,
    reset = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Anything not given comes from the configuration
    disk_size = get_boot_setting("vm_disk_size", DEFAULT_BOOT_DISK_SIZE, disk_size)
    memory = get_boot_setting("vm_memory", DEFAULT_BOOT_MEMORY, memory)
    vcpus = get_boot_setting("vm_vcpus", DEFAULT_BOOT_VCPUS, vcpus)
    ssh_port = get_boot_setting("vm_ssh_port", DEFAULT_SSH_PORT, ssh_port)

    # Check what this workstation is missing before anything is made
    missing = get_missing_boot_tools()
    if missing:
        logger.log_error("Missing tools: %s" % ", ".join(missing))
        return False
    firmware = get_firmware_pair()
    if not firmware:
        logger.log_error(
            "No uefi firmware found; install ovmf to boot an image the way "
            "the target machine will")
        return False
    if iso_file and not paths.is_path_file(iso_file):
        logger.log_error("Image not found: %s" % iso_file)
        return False
    firmware_code, firmware_template = firmware

    # Somewhere to keep the disk and the firmware variables
    target_dir = get_boot_dir(boot_dir)
    success = fileops.make_directory(
        src = target_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to create %s" % target_dir)
        return False
    disk_image = get_boot_disk(vm_name, boot_dir)
    firmware_vars = get_boot_firmware_vars(vm_name, boot_dir)

    # Start over when asked, so a second install is not laid over the first
    if reset:
        for stale in [disk_image, firmware_vars]:
            if paths.is_path_file(stale):
                fileops.remove_file(
                    src = stale,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

    # A disk to install onto, and firmware variables of its own
    if not paths.is_path_file(disk_image):
        success = create_boot_disk(
            disk_image = disk_image,
            disk_size = disk_size,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    elif iso_file and not reset:
        logger.log_warning(
            "%s already exists and will be installed over" % disk_image)
    success = prepare_boot_firmware(
        firmware_vars = firmware_vars,
        template_file = firmware_template,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to prepare firmware variables")
        return False

    # Say what will happen, since an install is a long wait at a window
    accelerated = is_acceleration_available()
    if not accelerated:
        logger.log_warning(
            "No access to /dev/kvm; the machine will run without "
            "acceleration and an install will take hours")
    if iso_file:
        logger.log_info("Installing from %s onto %s" % (iso_file, disk_image))
        logger.log_info("Qemu stops when the installer reboots, which is how it finishes")
    else:
        logger.log_info("Booting %s" % disk_image)
    if ssh_port:
        logger.log_info("Reach it with: ssh -p %d <user>@localhost" % ssh_port)

    # Run it
    code = command.run_interactive_command(
        cmd = get_boot_command(
            disk_image = disk_image,
            firmware_code = firmware_code,
            firmware_vars = firmware_vars,
            iso_file = iso_file,
            memory = memory,
            vcpus = vcpus,
            ssh_port = ssh_port,
            headless = headless,
            serial_file = serial_file,
            accelerated = accelerated),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0
