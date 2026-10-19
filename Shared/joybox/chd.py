# Imports
import os
import os.path
import re

# Local imports
import joybox.config as config
import joybox.fileops as fileops
import joybox.command as command
import joybox.programs as programs
import joybox.paths as paths
import joybox.serialization as serialization
import joybox.logger as logger
import joybox.iso as iso
import joybox.archive as archive

# Get disc iso
def get_disc_iso(chd_file):
    return chd_file.replace(config.DiscImageFileType.CHD.cval(), config.DiscImageFileType.ISO.cval())

# Get disc toc
def get_disc_toc(chd_file):
    return chd_file.replace(config.DiscImageFileType.CHD.cval(), config.DiscImageFileType.TOC.cval())

# Check if disc chd is mounted
def is_disc_chd_mounted(chd_file, mount_dir):
    return iso.is_iso_mounted(
        iso_file = get_disc_iso(chd_file),
        mount_dir = mount_dir)

# Create disc chd
def create_disc_chd(
    chd_file,
    source_iso,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = None
    if programs.is_tool_installed("MameChdman"):
        chd_tool = programs.get_tool_program("MameChdman")
    if not chd_tool:
        logger.log_error("MameChdman was not found")
        return False

    # Get create command
    create_command = [
        chd_tool,
        "createcd",
        "-i", source_iso,
        "-o", chd_file
    ]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = command.create_command_options(
            output_paths = [chd_file],
            blocking_processes = [chd_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = source_iso,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return os.path.exists(chd_file)

# Extract disc chd
def extract_disc_chd(
    chd_file,
    binary_file,
    toc_file,
    force_overwrite = False,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = None
    if programs.is_tool_installed("MameChdman"):
        chd_tool = programs.get_tool_program("MameChdman")
    if not chd_tool:
        logger.log_error("MameChdman was not found")
        return False

    # Get extract command
    extract_cmd = [
        chd_tool,
        "extractcd",
        "-i", chd_file,
        "-o", toc_file,
        "-ob", binary_file
    ]
    if force_overwrite:
        extract_cmd += ["--force"]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [toc_file, binary_file],
            blocking_processes = [chd_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = chd_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return os.path.exists(binary_file)

# Track types bchunk can split
bchunk_track_types = ["MODE1/2352", "MODE2/2352", "MODE2/2336", "AUDIO"]

# Track types that already hold plain 2048-byte iso sectors
iso_track_types = ["MODE1/2048", "MODE2/2048"]

# Get cue track types
def get_cue_track_types(cue_file):
    cue_text = serialization.read_text_file(cue_file) or ""
    return re.findall(r"^\s*TRACK\s+\d+\s+(\S+)", cue_text, flags = re.MULTILINE | re.IGNORECASE)

# Extract disc chd to iso
def extract_disc_chd_to_iso(
    chd_file,
    iso_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    bchunk_tool = None
    if programs.is_tool_installed("Bchunk"):
        bchunk_tool = programs.get_tool_program("Bchunk")
    if not bchunk_tool:
        logger.log_error("Bchunk was not found")
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Extract cue/bin from chd
    tmp_basename = paths.get_filename_basename(chd_file)
    tmp_bin = paths.join_paths(tmp_dir_result, tmp_basename + ".bin")
    tmp_cue = paths.join_paths(tmp_dir_result, tmp_basename + config.DiscImageFileType.CUE.cval())
    success = extract_disc_chd(
        chd_file = chd_file,
        binary_file = tmp_bin,
        toc_file = tmp_cue,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        fileops.remove_directory(src = tmp_dir_result, verbose = verbose, pretend_run = pretend_run)
        return False

    # A pretend run has no cue to read
    if pretend_run:
        return True

    # A lone 2048-byte data track is already an iso; bchunk cannot read one
    track_types = get_cue_track_types(tmp_cue)
    tracks_dir = paths.join_paths(tmp_dir_result, "tracks")
    fileops.make_directory(src = tracks_dir, verbose = verbose)
    if len(track_types) == 1 and track_types[0] in iso_track_types:
        success = fileops.move_file_or_directory(
            src = tmp_bin,
            dest = paths.join_paths(tracks_dir, paths.get_filename_file(iso_file)),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            fileops.remove_directory(src = tmp_dir_result, verbose = verbose)
            return False

    # Split tracks with bchunk, which numbers each one (Game01.iso, Game02.cdr, ...)
    else:
        unsupported_types = sorted(set(track_types) - set(bchunk_track_types))
        if not track_types or unsupported_types:
            logger.log_error("Bchunk cannot split the tracks of %s (%s)" % (chd_file, ", ".join(unsupported_types) or "no tracks"))
            fileops.remove_directory(src = tmp_dir_result, verbose = verbose)
            return False
        bchunk_cmd = [
            bchunk_tool,
            tmp_bin,
            tmp_cue,
            paths.join_paths(tracks_dir, paths.get_filename_basename(iso_file))
        ]
        code = command.run_returncode_command(
            cmd = bchunk_cmd,
            options = command.create_command_options(
                blocking_processes = [bchunk_tool]),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if code != 0:
            fileops.remove_directory(src = tmp_dir_result, verbose = verbose)
            return False

    # Move tracks beside the iso, naming a lone track after the iso itself
    track_files = sorted(paths.get_directory_contents(tracks_dir))
    if not track_files:
        logger.log_error("Bchunk wrote no tracks for %s" % chd_file)
        fileops.remove_directory(src = tmp_dir_result, verbose = verbose)
        return False
    for track_file in track_files:
        dest_file = iso_file
        if len(track_files) > 1:
            dest_file = paths.join_paths(paths.get_filename_directory(iso_file), track_file)
        success = fileops.move_file_or_directory(
            src = paths.join_paths(tracks_dir, track_file),
            dest = dest_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            fileops.remove_directory(src = tmp_dir_result, verbose = verbose)
            return False

    # Clean up
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if delete_original:
        fileops.remove_file(
            src = chd_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Check result
    return True

# Archive disc chd
def archive_disc_chd(
    chd_file,
    zip_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Mount chd
    success = mount_disc_chd(
        chd_file = chd_file,
        mount_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Archive contents
    success = archive.create_archive_from_folder(
        archive_file = zip_file,
        source_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = chd_file,
            verbose = verbose,
            pretend_run = pretend_run)
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(zip_file)

# Verify disc chd
def verify_disc_chd(
    chd_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = None
    if programs.is_tool_installed("MameChdman"):
        chd_tool = programs.get_tool_program("MameChdman")
    if not chd_tool:
        logger.log_error("MameChdman was not found")
        return False

    # Get verify command
    verify_cmd = [
        chd_tool,
        "verify",
        "-i", chd_file
    ]

    # Run verify command
    verify_output = command.run_output_command(
        cmd = verify_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check verification
    verify_text = verify_output
    if isinstance(verify_output, bytes):
        verify_text = verify_output.decode()
    return "Overall SHA1 verification successful!" in verify_text

# Mount disc chd
def mount_disc_chd(
    chd_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if is_disc_chd_mounted(chd_file, mount_dir):
        return True

    # Extract iso from chd
    success = extract_disc_chd(
        chd_file = chd_file,
        binary_file = get_disc_iso(chd_file),
        toc_file = get_disc_toc(chd_file),
        force_overwrite = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Mount iso
    success = iso.mount_iso(
        iso_file = get_disc_iso(chd_file),
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return is_disc_chd_mounted(chd_file, mount_dir)

# Unmount disc chd
def unmount_disc_chd(
    chd_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if not is_disc_chd_mounted(chd_file, mount_dir):
        return True

    # Unmount iso
    success = iso.unmount_iso(
        iso_file = get_disc_iso(chd_file),
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return not is_disc_chd_mounted(chd_file, mount_dir)
