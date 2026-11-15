# Drives inside a Wine or Sandboxie prefix: mounting disc images and
# directories on free drive letters, and unmounting them.

# Imports

# Local imports
from joybox import config
from joybox import validation
from joybox import fileops
from joybox import paths
from joybox import sandbox

###########################################################

# Find first available real drive path
def find_first_available_real_drive_path(options):

    # Check params
    validation.assert_path_exists(options.get_prefix_dir(), "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get drive path and check if its available
        drive_path = sandbox.get_real_drive_path(
            options = options,
            drive = letter)
        if not paths.does_path_exist(drive_path):
            return drive_path

    # Nothing available
    return None

# Find first taken real drive path
def find_first_taken_real_drive_path(src, options):

    # Check params
    validation.assert_path_exists(src, "src")
    validation.assert_path_exists(options.get_prefix_dir(), "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get drive path and check if its available
        drive_path = sandbox.get_real_drive_path(
            options = options,
            drive = letter)
        if paths.does_path_exist(drive_path):
            if src == fileops.resolve_symlink(drive_path):
                return drive_path

    # Nothing found
    return None

# Mount disc image
def mount_disc_image(
    src,
    mount_dir,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Imports
    import joybox.chd as chd

    # Check params
    validation.assert_path_exists(src, "src")

    # Mount disc
    success = chd.mount_disc_chd(
        chd_file = src,
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Mount directory
    success = mount_directory(
        src = mount_dir,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        chd.unmount_disc_chd(
            chd_file = src,
            mount_dir = mount_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        return False
    return True

# Unmount disc image
def unmount_disc_image(
    src,
    mount_dir,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Imports
    import joybox.chd as chd

    # Check params
    validation.assert_path_exists(src, "src")

    # Unmount directory
    unmounted_directory = unmount_directory(
        src = mount_dir,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Unmount disc, even when no drive pointed at it
    unmounted_disc = chd.unmount_disc_chd(
        chd_file = src,
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return unmounted_directory and unmounted_disc

# Mount directory
def mount_directory(
    src,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_path_exists(src, "src")
    validation.assert_path_exists(options.get_prefix_dir(), "prefix_dir")

    # Get first available drive path
    drive_path = find_first_available_real_drive_path(options)
    if not paths.is_path_valid(drive_path):
        return False

    # Create symlink
    return fileops.create_symlink(
        src = src,
        dest = drive_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Unmount directory
def unmount_directory(
    src,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_path_exists(src, "src")
    validation.assert_path_exists(options.get_prefix_dir(), "prefix_dir")

    # Get first taken drive path
    drive_path = find_first_taken_real_drive_path(src, options)
    if not paths.is_path_valid(drive_path):
        return False

    # Remove the drive symlink, not what it points at
    return fileops.remove_symlink(
        src = drive_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Unmount all mounted drives
def unmount_all_mounted_drives(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_path_exists(options.get_prefix_dir(), "prefix_dir")

    # Only go through potentially available drives
    success = True
    for letter in config.drives_regular:

        # Get real drive path
        drive_path = sandbox.get_real_drive_path(
            options = options,
            drive = letter)

        # Remove symlink
        if not fileops.remove_symlink(
            src = drive_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            success = False
    return success
