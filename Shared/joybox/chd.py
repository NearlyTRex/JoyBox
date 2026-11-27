# Imports
import os
import os.path
import re

# Local imports
from joybox import config
from joybox import fileops
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import paths
from joybox import serialization
from joybox import logger
from joybox import iso
from joybox import mds
from joybox import archive

# Check if a file is a chd disc image
def is_chd_file(path):
    return path.endswith(config.DiscImageFileType.CHD.cval())

# The .iso path beside a chd, where mounting extracts its image
def get_disc_iso(chd_file):
    return chd_file.replace(config.DiscImageFileType.CHD.cval(), config.DiscImageFileType.ISO.cval())

# The .toc path beside a chd, where mounting extracts its track sheet
def get_disc_toc(chd_file):
    return chd_file.replace(config.DiscImageFileType.CHD.cval(), config.DiscImageFileType.TOC.cval())

# Check if disc chd is mounted
def is_disc_chd_mounted(chd_file, mount_dir):
    return iso.is_iso_mounted(
        iso_file = get_disc_iso(chd_file),
        mount_dir = mount_dir)

# Converters for disc images chdman cannot read, by extension
# A converter is called as converter(source_file, output_dir, verbose, pretend_run,
# exit_on_failure). It writes a sheet chdman reads (cue, toc or gdi) into the empty
# output_dir and returns (sheet file, source files the sheet stands for), or None.
disc_sheet_converters = {
    config.DiscImageFileType.MDS.cval(): mds.convert_mds_to_cue,
}

# Register a converter for disc images with an extension
def register_disc_sheet_converter(extension, converter):
    disc_sheet_converters[extension.lower()] = converter

# Get the converter for a disc image, or None when chdman reads it directly
def get_disc_sheet_converter(source_file):
    for extension, converter in disc_sheet_converters.items():
        if source_file.lower().endswith(extension):
            return converter
    return None

# Run a chdman command that writes the output paths; True when it exits 0
def _run_chdman_command(chd_tool, chdman_cmd, output_paths, verbose, pretend_run, exit_on_failure):
    code = command.run_returncode_command(
        cmd = chdman_cmd,
        options = commandbase.create_command_options(
            output_paths = output_paths,
            blocking_processes = [chd_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Remove the file chdman read when delete_original is set
def _remove_original_file(original_file, delete_original, verbose, pretend_run, exit_on_failure):
    if delete_original:
        fileops.remove_file(
            src = original_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Whether chdman's output exists; always True in a pretend run, which writes nothing
def _does_output_exist(output_file, pretend_run):
    if pretend_run:
        return True
    return os.path.exists(output_file)

# Compress a disc image into a chd with chdman createcd, converting formats chdman cannot read first
def create_disc_chd(
    chd_file,
    source_iso,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # An image chdman cannot read goes through its converter
    converter = get_disc_sheet_converter(source_iso)
    if converter:
        return create_disc_chd_with_converter(
            chd_file = chd_file,
            source_file = source_iso,
            converter = converter,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Otherwise chdman reads it directly
    return _create_disc_chd_directly(chd_file, source_iso, delete_original, verbose, pretend_run, exit_on_failure)

# Compress an image chdman reads into a chd with chdman createcd
def _create_disc_chd_directly(chd_file, source_iso, delete_original, verbose, pretend_run, exit_on_failure):

    # Get tool
    chd_tool = programs.find_tool_program("MameChdman")
    if not chd_tool:
        return False

    # Get create command
    create_command = [
        chd_tool,
        "createcd",
        "-i", source_iso,
        "-o", chd_file
    ]

    # Run create command
    if not _run_chdman_command(chd_tool, create_command, [chd_file], verbose, pretend_run, exit_on_failure):
        return False

    # Clean up
    _remove_original_file(source_iso, delete_original, verbose, pretend_run, exit_on_failure)

    # Check result
    return _does_output_exist(chd_file, pretend_run)

# Create disc chd from an image through its converter
def create_disc_chd_with_converter(
    chd_file,
    source_file,
    converter,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Write a sheet chdman reads in a temporary directory, then convert it
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        converted = converter(
            source_file = source_file,
            output_dir = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        success = bool(converted) and create_disc_chd(
            chd_file = chd_file,
            source_iso = converted[0],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean up
    if delete_original:
        for src in converted[1]:
            fileops.remove_file(src = src, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    return True

# Unpack a chd into a binary image and track sheet with chdman extractcd; False when the binary is missing after
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
    chd_tool = programs.find_tool_program("MameChdman")
    if not chd_tool:
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
    if not _run_chdman_command(chd_tool, extract_cmd, [toc_file, binary_file], verbose, pretend_run, exit_on_failure):
        return False

    # Clean up
    _remove_original_file(chd_file, delete_original, verbose, pretend_run, exit_on_failure)

    # Check result
    return _does_output_exist(binary_file, pretend_run)

# Track types bchunk can split
bchunk_track_types = ["MODE1/2352", "MODE2/2352", "MODE2/2336", "AUDIO"]

# Track types that already hold plain 2048-byte iso sectors
iso_track_types = ["MODE1/2048", "MODE2/2048"]

# Mode of each TRACK line in a cue sheet, such as MODE1/2352 or AUDIO; empty when it is unreadable
def get_cue_track_types(cue_file):
    cue_text = serialization.read_text_file(cue_file) or ""
    return re.findall(r"^\s*TRACK\s+\d+\s+(\S+)", cue_text, flags = re.MULTILINE | re.IGNORECASE)

# Split a cue/bin's tracks into a directory. bchunk cannot read a lone 2048-byte data track,
# so that is moved as the iso itself; any others bchunk splits into numbered tracks.
def split_cue_bin_tracks(bchunk_tool, chd_file, bin_file, cue_file, tracks_dir, iso_file, verbose = False, exit_on_failure = False):
    track_types = get_cue_track_types(cue_file)
    if len(track_types) == 1 and track_types[0] in iso_track_types:
        return fileops.move_file_or_directory(
            src = bin_file,
            dest = paths.join_paths(tracks_dir, paths.get_filename_file(iso_file)),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    unsupported_types = sorted(set(track_types) - set(bchunk_track_types))
    if not track_types or unsupported_types:
        logger.log_error("Bchunk cannot split the tracks of %s (%s)" % (chd_file, ", ".join(unsupported_types) or "no tracks"))
        return False
    code = command.run_returncode_command(
        cmd = [bchunk_tool, bin_file, cue_file, paths.join_paths(tracks_dir, paths.get_filename_basename(iso_file))],
        options = commandbase.create_command_options(
            blocking_processes = [bchunk_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Move split tracks beside the iso, naming a lone track after the iso itself
def move_split_tracks(chd_file, tracks_dir, iso_file, verbose = False, exit_on_failure = False):
    track_files = sorted(paths.get_directory_contents(tracks_dir))
    if not track_files:
        logger.log_error("Bchunk wrote no tracks for %s" % chd_file)
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
            return False
    return True

# Unpack a chd to cue/bin and split it into an iso, or numbered tracks beside it for multi-track discs, with bchunk
def extract_disc_chd_to_iso(
    chd_file,
    iso_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    bchunk_tool = programs.find_tool_program("Bchunk")
    if not bchunk_tool:
        return False

    # Extract cue/bin from chd in a temporary directory, then split its tracks out
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        tmp_base = paths.join_paths(tmp_dir, paths.get_filename_basename(chd_file))
        tmp_bin, tmp_cue = tmp_base + ".bin", tmp_base + config.DiscImageFileType.CUE.cval()
        success = extract_disc_chd(
            chd_file = chd_file,
            binary_file = tmp_bin,
            toc_file = tmp_cue,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # A pretend run has no cue to read
        if pretend_run:
            return True
        tracks_dir = paths.join_paths(tmp_dir, "tracks")
        fileops.make_directory(src = tracks_dir, verbose = verbose)
        if not split_cue_bin_tracks(bchunk_tool, chd_file, tmp_bin, tmp_cue, tracks_dir, iso_file, verbose, exit_on_failure):
            return False
        if not move_split_tracks(chd_file, tracks_dir, iso_file, verbose, exit_on_failure):
            return False
    if delete_original:
        fileops.remove_file(src = chd_file, verbose = verbose, exit_on_failure = exit_on_failure)
    return True

# Mount a chd in a directory and archive its contents, unmounting before the directory goes
# and deleting the iso and toc that mounting extracted beside the chd
def archive_mounted_disc_chd(chd_file, zip_file, mount_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        success = mount_disc_chd(
            chd_file = chd_file,
            mount_dir = mount_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        try:
            return archive.create_archive_from_folder(
                archive_file = zip_file,
                source_dir = mount_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        finally:
            unmount_disc_chd(
                chd_file = chd_file,
                mount_dir = mount_dir,
                verbose = verbose,
                pretend_run = pretend_run)
    finally:
        for extracted_file in (get_disc_iso(chd_file), get_disc_toc(chd_file)):
            fileops.remove_file(src = extracted_file, verbose = verbose, pretend_run = pretend_run)

# Zip the files on a chd disc by mounting it in a temporary directory; False unless the zip exists
def archive_disc_chd(
    chd_file,
    zip_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Mount chd in a temporary directory and archive its contents
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        if not archive_mounted_disc_chd(chd_file, zip_file, tmp_dir, verbose, pretend_run, exit_on_failure):
            return False
    if delete_original:
        fileops.remove_file(
            src = chd_file,
            verbose = verbose,
            pretend_run = pretend_run)
    return os.path.exists(zip_file)

# Whether chdman verify reports the chd's overall SHA1 as matching
def verify_disc_chd(
    chd_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = programs.find_tool_program("MameChdman")
    if not chd_tool:
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

# Extract a chd to an iso beside it and mount that at the directory; True when it is already mounted
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

# Unmount the iso extracted from a chd; True when it was not mounted
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

# Convert each disc image of the given types under input_path into a chd beside it, skipping
# images whose chd already exists
def convert_disc_images_to_chd(
    input_path,
    disc_image_types,
    delete_originals = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    disc_image_extensions = [disc_image_type.cval() for disc_image_type in disc_image_types]
    for current_file in paths.build_file_list_by_extensions(input_path, extensions = disc_image_extensions):
        output_chd = paths.change_filename_extension(current_file, config.DiscImageFileType.CHD.cval())
        if paths.does_path_exist(output_chd):
            continue
        create_disc_chd(
            chd_file = output_chd,
            source_iso = current_file,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Extract a chd into an iso beside it, unless the iso or its first numbered track exists
def _extract_chd_to_sibling_iso(chd_file, delete_originals, verbose, pretend_run, exit_on_failure):
    output_iso = paths.change_filename_extension(chd_file, ".iso")
    output_track = paths.change_filename_extension(chd_file, "01.iso")
    if paths.does_path_exist(output_iso) or paths.does_path_exist(output_track):
        return
    extract_disc_chd_to_iso(
        chd_file = chd_file,
        iso_file = output_iso,
        delete_original = delete_originals,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Extract a chd into a binary and toc file beside it, unless either exists
def _extract_chd_to_sibling_toc(chd_file, extract_format, bin_ext, delete_originals, verbose, pretend_run, exit_on_failure):
    output_bin = paths.change_filename_extension(chd_file, bin_ext)
    output_toc = paths.change_filename_extension(chd_file, extract_format.cval())
    if paths.does_path_exist(output_bin) or paths.does_path_exist(output_toc):
        return
    extract_disc_chd(
        chd_file = chd_file,
        binary_file = output_bin,
        toc_file = output_toc,
        delete_original = delete_originals,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Extract each chd under input_path beside itself, as an iso for the ISO format or else as a
# binary file with bin_ext and a toc of the format, skipping chds whose outputs exist
def extract_disc_chds(
    input_path,
    extract_format,
    bin_ext,
    delete_originals = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for current_file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):
        if extract_format == config.DiscExtractFormatType.ISO:
            _extract_chd_to_sibling_iso(current_file, delete_originals, verbose, pretend_run, exit_on_failure)
        else:
            _extract_chd_to_sibling_toc(current_file, extract_format, bin_ext, delete_originals, verbose, pretend_run, exit_on_failure)

# Zip the files on each chd under input_path beside it, skipping chds whose zip exists
def archive_disc_chds(
    input_path,
    delete_originals = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for current_file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):
        output_zip = paths.change_filename_extension(current_file, config.ArchiveFileType.ZIP.cval())
        if paths.does_path_exist(output_zip):
            continue
        archive_disc_chd(
            chd_file = current_file,
            zip_file = output_zip,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
