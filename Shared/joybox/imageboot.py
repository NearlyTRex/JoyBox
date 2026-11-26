# Booting an installer image directly in qemu.
#
# The virtualmachine guests start from a cloud image that is already installed.
# Testing an installer image is the other way round: a blank disk, the image
# in the drive, and firmware that boots it the way the target machine will.
# That is qemu on its own, since nothing here needs to outlive the test and
# nothing needs libvirt to manage it.

# Imports
import os

# Local imports
from joybox import command
from joybox import commandbase
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import settings

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
    return [tool for tool in BOOT_TOOLS if not commandbase.is_runnable_command(tool)]

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

# Build the command that boots a machine: from the image, stopping when the installer
# reboots, when there is one to install, else from the disk
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
        logger.log_info("Qemu stops when the installer powers off or reboots, which is how it finishes")
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
