# Building releases from source: fetching the source, applying patches,
# running the build and installing what it produced.

# Imports
import os

# Local imports
from joybox import archive
from joybox import archiveinfo
from joybox import command
from joybox import commandbase
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import locker
from joybox import logger
from joybox import network
from joybox import paths
from joybox import programs
from joybox import release
from joybox import serialization
from joybox import webfetch

# Resolve a source patch entry to its filename and contents
def resolve_patch_entry(patch_entry, verbose = False, exit_on_failure = False):
    patch_file = patch_entry.get("file") or ""
    patch_content = patch_entry.get("content") or ""
    patch_path = patch_entry.get("path") or ""
    if patch_path and os.path.isfile(patch_path):
        patch_content = serialization.read_text_file(
            src = patch_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if patch_content is None:
            return None, None
        if not patch_file:
            patch_file = os.path.basename(patch_path)
    return patch_file, patch_content

# Apply source patches with git apply
# Apply source patches with git apply
def apply_source_patches(
    source_patches,
    source_dir,
    patch_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not isinstance(source_patches, list):
        return True
    for patch_index, patch_entry in enumerate(source_patches):
        patch_file, patch_content = _resolve_named_patch(patch_index, patch_entry, verbose, exit_on_failure)
        if not patch_file:
            return False
        success = _write_and_apply_patch(
            patch_file = patch_file,
            patch_content = patch_content,
            source_dir = source_dir,
            patch_dir = patch_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Resolve a patch entry, naming it after its index when it has no filename
# Logs and returns (None, None) when it cannot be read or has no content
def _resolve_named_patch(patch_index, patch_entry, verbose, exit_on_failure):
    patch_file, patch_content = resolve_patch_entry(
        patch_entry = patch_entry,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if patch_file is None:
        logger.log_error("Unable to read patch file '%s'" % patch_entry.get("path"))
        return None, None
    if not patch_content:
        logger.log_error("Patch entry %d has no content" % patch_index)
        return None, None
    if not patch_file:
        patch_file = "source_patch_%d" % patch_index
    return patch_file, patch_content

# Write a patch as a .patch file in patch_dir and git apply it in source_dir; False on failure
def _write_and_apply_patch(patch_file, patch_content, source_dir, patch_dir, verbose, pretend_run, exit_on_failure):

    # Write patch to temp file
    patch_temp_file = paths.join_paths(patch_dir, patch_file if patch_file.endswith(".patch") else patch_file + ".patch")
    success = fileops.touch_file(
        src = patch_temp_file,
        contents = patch_content,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to write patch file '%s'" % patch_temp_file)
        return False

    # Apply patch with git apply
    code = command.run_returncode_command(
        cmd = [
            programs.get_tool_program("Git"),
            "apply",
            patch_temp_file
        ],
        options = commandbase.create_command_options(
            cwd = source_dir),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to apply patch '%s'" % patch_file)
        return False
    return True

# Fetch source by git or archive into a temp dir, apply patches and run build_cmd there
# Returns the tmp, source and build dirs, or None on failure with the temp dir removed
def build_from_source(
    release_url = "",
    release_branch = "",
    webpage_url = "",
    webpage_base_url = "",
    starts_with = "",
    ends_with = "",
    build_cmd = "",
    build_dir = "",
    source_patches = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get source patches
    source_patches = [] if source_patches is None else source_patches

    # Find release url if necessary
    found, release_url = _resolve_release_url(
        release_url, webpage_url, webpage_base_url, starts_with, ends_with, verbose, pretend_run, exit_on_failure)
    if not found:
        return None

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        logger.log_error("Unable to create temporary directory")
        return None

    build_info = None
    try:
        build_info = _fetch_and_build_source(
            tmp_dir_result, release_url, release_branch, build_cmd, build_dir, source_patches,
            verbose, pretend_run, exit_on_failure)
        return build_info
    finally:
        if not build_info:
            release.remove_temporary_directory(tmp_dir_result, verbose = verbose, pretend_run = pretend_run)

# Whether a release url was found, and the url: the latest match on webpage_url when one is given
def _resolve_release_url(release_url, webpage_url, webpage_base_url, starts_with, ends_with, verbose, pretend_run, exit_on_failure):
    if not webpage_url:
        return True, release_url
    release_url = webfetch.get_matching_url(
        url = webpage_url,
        base_url = webpage_base_url,
        starts_with = starts_with,
        ends_with = ends_with,
        get_latest = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not release_url:
        logger.log_error("No release url could be found from webpage %s" % webpage_url)
        return False, None
    return True, release_url

# Make each folder in order, logging the first that cannot be made; False then
def _make_folders(folders, verbose, pretend_run, exit_on_failure):
    for folder in folders:
        success = fileops.make_directory(
            src = folder,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to make folder '%s'" % folder)
            return False
    return True

# Download the release into tmp_dir, patch it and run build_cmd in its build dir
# Returns the tmp, source and build dirs, or None at the first failing step
def _fetch_and_build_source(tmp_dir, release_url, release_branch, build_cmd, build_dir, source_patches, verbose, pretend_run, exit_on_failure):

    # Get directories
    source_base_dir = paths.join_paths(tmp_dir, "Source")
    download_dir = paths.join_paths(tmp_dir, "Download")

    # Make folders
    if not _make_folders([source_base_dir, download_dir], verbose, pretend_run, exit_on_failure):
        return None

    # Download sources
    if not release_url:
        logger.log_error("No release url was given")
        return None
    if release_url.rstrip("/").endswith(".git"):
        source_dir = _download_git_source(release_url, release_branch, source_base_dir, verbose, pretend_run, exit_on_failure)
    else:
        source_dir = _download_archive_source(release_url, source_base_dir, download_dir, verbose, pretend_run, exit_on_failure)
    if not source_dir:
        return None

    # Get build directory
    source_build_dir = source_dir
    if build_dir:
        source_build_dir = os.path.abspath(paths.join_paths(source_dir, build_dir))

    # Patch and build
    success = _patch_and_build(tmp_dir, source_dir, source_build_dir, build_cmd, source_patches, verbose, pretend_run, exit_on_failure)
    if not success:
        return None

    # Return build info
    return {
        "tmp_dir": tmp_dir,
        "source_dir": source_dir,
        "build_dir": source_build_dir
    }

# Clone a git release into a folder named after its repo under source_base_dir; that folder, or None
def _download_git_source(release_url, release_branch, source_base_dir, verbose, pretend_run, exit_on_failure):

    # Get repo name
    repo_name = paths.get_filename_basename(release_url.rstrip("/"))
    source_dir = paths.join_paths(source_base_dir, repo_name)

    # Download git release
    success = network.download_git_url(
        url = release_url,
        output_dir = source_dir,
        branch = release_branch if release_branch else None,
        clean = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download release from '%s'" % release_url)
        return None
    return source_dir

# Download a source archive into download_dir and extract it under source_base_dir; that folder, or None
def _download_archive_source(release_url, source_base_dir, download_dir, verbose, pretend_run, exit_on_failure):

    # Get archive info
    archive_basename = paths.get_filename_basename(release_url)
    archive_extension = paths.get_filename_extension(release_url)
    archive_file = paths.join_paths(download_dir, archive_basename + archive_extension)
    source_dir = paths.join_paths(source_base_dir, archive_basename)

    # Download source archive
    success = network.download_url(
        url = release_url,
        output_file = archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download release from '%s'" % release_url)
        return None

    # Extract source archive
    success = archive.extract_archive(
        archive_file = archive_file,
        extract_dir = source_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to extract source archive")
        return None
    return source_dir

# Apply the source patches, make the build folder and run build_cmd in it as a shell command
def _patch_and_build(tmp_dir, source_dir, source_build_dir, build_cmd, source_patches, verbose, pretend_run, exit_on_failure):

    # Apply source patches
    success = apply_source_patches(
        source_patches = source_patches,
        source_dir = source_dir,
        patch_dir = tmp_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Make build folder
    success = fileops.make_directory(
        src = source_build_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to make build folder '%s'" % source_build_dir)
        return False

    # Build release
    code = command.run_returncode_command(
        cmd = build_cmd,
        options = commandbase.create_command_options(
            cwd = source_build_dir,
            is_shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to build release")
        return False
    return True

# Run build_from_source for an installing builder, which passes these settings through unchanged
def _build_release(release_url, release_branch, webpage_url, webpage_base_url, starts_with, ends_with, build_cmd, build_dir, source_patches, verbose, pretend_run, exit_on_failure):
    return build_from_source(
        release_url = release_url,
        release_branch = release_branch,
        webpage_url = webpage_url,
        webpage_base_url = webpage_base_url,
        starts_with = starts_with,
        ends_with = ends_with,
        build_cmd = build_cmd,
        build_dir = build_dir,
        source_patches = source_patches,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The last file under search_dir ending in output_file, or its expected path in a pretend run
# Logs and returns None when nothing was built
def _find_built_file(search_dir, output_file, pretend_run):
    built_file = None
    for path in paths.build_file_list(search_dir):
        if path.endswith(output_file):
            built_file = path
    if not built_file and pretend_run:
        built_file = paths.join_paths(search_dir, output_file)
    if not built_file:
        logger.log_error("No built files could be found")
        return None
    return built_file

# Copy each external object from the temp dir into the install dir; False at the first failure
def _copy_external_objects(tmp_dir, install_dir, external_copies, verbose, pretend_run, exit_on_failure):
    for obj in external_copies:
        src_obj = paths.join_paths(tmp_dir, obj["from"])
        dest_obj = paths.join_paths(install_dir, obj["to"])
        success = filebulk.smart_copy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy other files")
            return False
    return True

# Back the built file up to the locker as final_file under backups_dir, unless skipped or no backups dir
# A failed backup is noted rather than failing the install
def _backup_built_file(built_file, backups_dir, final_file, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure):
    if not skip_autobackup and paths.is_path_valid(backups_dir):
        backup_dest = paths.join_paths(backups_dir, final_file)
        dest_rel_path = locker.convert_to_relative_path(backup_dest)
        success = locker.backup(
            src = built_file,
            dest_rel_path = dest_rel_path,
            locker_type = locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            release.note_failed_backup(backup_dest)

# Build from source, then install the built file (extracting it if an archive) and extra copies into install_dir
# Backs up to the locker unless skipped; False on failure
def build_binary_from_source(
    release_url = "",
    release_branch = "",
    webpage_url = "",
    webpage_base_url = "",
    starts_with = "",
    ends_with = "",
    output_file = "",
    output_dir = "",
    search_file = "",
    install_name = "",
    install_dir = "",
    backups_dir = "",
    build_cmd = "",
    build_dir = "",
    external_copies = (),
    source_patches = None,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build from source
    build_info = _build_release(
        release_url, release_branch, webpage_url, webpage_base_url, starts_with, ends_with,
        build_cmd, build_dir, source_patches, verbose, pretend_run, exit_on_failure)
    if not build_info:
        return False

    # Install build result
    try:
        return _install_built_binary(
            build_info, output_file, output_dir, search_file, install_name, install_dir, backups_dir,
            external_copies, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure)
    finally:
        release.remove_temporary_directory(build_info["tmp_dir"], verbose = verbose, pretend_run = pretend_run)

# Install the built binary, extra copies and backup from a finished build; whether install_dir has files
def _install_built_binary(build_info, output_file, output_dir, search_file, install_name, install_dir, backups_dir, external_copies, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure):
    tmp_dir = build_info["tmp_dir"]
    source_dir = build_info["source_dir"]

    # Make install folder
    success = fileops.make_directory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to make install folder '%s'" % install_dir)
        return False

    # Determine search directory for built files
    search_dir = tmp_dir
    if output_dir:
        search_dir = paths.join_paths(source_dir, output_dir)

    # Find built release file
    built_file = _find_built_file(search_dir, output_file, pretend_run)
    if not built_file:
        return False

    # Install release and other objects
    final_file = _get_final_binary_name(install_name, output_file)
    success = _install_binary_file(built_file, tmp_dir, install_dir, final_file, search_file, verbose, pretend_run, exit_on_failure)
    if not success:
        return False
    if not _copy_external_objects(tmp_dir, install_dir, external_copies, verbose, pretend_run, exit_on_failure):
        return False

    # Backup files
    _backup_built_file(built_file, backups_dir, final_file, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return paths.does_directory_contain_files(install_dir)

# Install name with the output file's extension, or with output_file itself when it is a bare extension
def _get_final_binary_name(install_name, output_file):
    if output_file.startswith("."):
        return install_name + output_file
    return install_name + paths.get_filename_extension(output_file)

# Install the built file's archive contents when search_file is set, otherwise copy it as final_file
def _install_binary_file(built_file, tmp_dir, install_dir, final_file, search_file, verbose, pretend_run, exit_on_failure):

    # Check if output is an archive that needs extraction
    is_archive = archiveinfo.is_archive(built_file)
    if is_archive and search_file:
        return _install_archive_contents(built_file, tmp_dir, install_dir, search_file, verbose, pretend_run, exit_on_failure)

    # Copy release file directly
    return _copy_release_file(built_file, install_dir, final_file, verbose, pretend_run, exit_on_failure)

# Copy the built file into install_dir as final_file; False when the copy fails
def _copy_release_file(built_file, install_dir, final_file, verbose, pretend_run, exit_on_failure):
    success = filebulk.smart_copy(
        src = built_file,
        dest = paths.join_paths(install_dir, final_file),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to copy release files")
        return False
    return True

# Extract a built archive and copy the folder holding search_file into install_dir
def _install_archive_contents(built_file, tmp_dir, install_dir, search_file, verbose, pretend_run, exit_on_failure):

    # Extract archive and install contents
    extract_dir = paths.join_paths(tmp_dir, "Extract")
    success = archive.extract_archive(
        archive_file = built_file,
        extract_dir = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to extract built archive")
        return False

    # Find directory containing search_file
    search_dir = extract_dir
    for file in paths.build_file_list(extract_dir):
        if file.endswith(search_file):
            search_dir = paths.get_filename_directory(file)
            break

    # Copy contents to install directory
    success = filebulk.copy_contents(
        src = search_dir,
        dest = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to copy release files")
        return False
    return True

# Build from source, assemble and package an AppImage, then install it and extra copies into install_dir
# Backs up to the locker unless skipped; False on failure
def build_appimage_from_source(
    release_url = "",
    release_branch = "",
    webpage_url = "",
    webpage_base_url = "",
    starts_with = "",
    ends_with = "",
    output_file = "",
    install_name = "",
    install_dir = "",
    backups_dir = "",
    build_cmd = "",
    build_dir = "",
    internal_copies = (),
    internal_symlinks = (),
    external_copies = (),
    source_patches = None,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build from source
    build_info = _build_release(
        release_url, release_branch, webpage_url, webpage_base_url, starts_with, ends_with,
        build_cmd, build_dir, source_patches, verbose, pretend_run, exit_on_failure)
    if not build_info:
        return False

    # Install build result
    try:
        return _install_built_appimage(
            build_info["tmp_dir"], output_file, install_name, install_dir, backups_dir, internal_copies, internal_symlinks,
            external_copies, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure)
    finally:
        release.remove_temporary_directory(build_info["tmp_dir"], verbose = verbose, pretend_run = pretend_run)

# Package the build in tmp_dir as an AppImage and install it, extra copies and backup; whether it was installed
def _install_built_appimage(tmp_dir, output_file, install_name, install_dir, backups_dir, internal_copies, internal_symlinks, external_copies, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure):
    appimage_dir = paths.join_paths(tmp_dir, "AppImage")

    # Make folders
    if not _make_folders([install_dir, appimage_dir], verbose, pretend_run, exit_on_failure):
        return False

    # Assemble and build AppImage
    success = _package_appimage(tmp_dir, appimage_dir, internal_copies, internal_symlinks, verbose, pretend_run, exit_on_failure)
    if not success:
        return False

    # Find built release file
    built_file = _find_built_file(tmp_dir, output_file, pretend_run)
    if not built_file:
        return False

    # Get final file
    final_file = install_name + ".AppImage"

    # Copy release file
    if not _copy_release_file(built_file, install_dir, final_file, verbose, pretend_run, exit_on_failure):
        return False

    # Copy other objects
    if not _copy_external_objects(tmp_dir, install_dir, external_copies, verbose, pretend_run, exit_on_failure):
        return False

    # Backup files
    _backup_built_file(built_file, backups_dir, final_file, locker_type, skip_autobackup, verbose, pretend_run, exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return os.path.exists(paths.join_paths(install_dir, final_file))

# Copy and symlink the AppImage objects into place, then run AppImageTool on appimage_dir
def _package_appimage(tmp_dir, appimage_dir, internal_copies, internal_symlinks, verbose, pretend_run, exit_on_failure):
    if not _copy_appimage_objects(tmp_dir, internal_copies, verbose, pretend_run, exit_on_failure):
        return False
    if not _symlink_appimage_objects(appimage_dir, internal_symlinks, verbose, pretend_run, exit_on_failure):
        return False

    # Build AppImage
    code = command.run_returncode_command(
        cmd = [programs.get_tool_program("AppImageTool"), appimage_dir],
        options = commandbase.create_command_options(
            cwd = tmp_dir),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to create AppImage from built release")
        return False
    return True

# Copy each internal object within the temp dir, taking AppImageTool objects from the tools root
def _copy_appimage_objects(tmp_dir, internal_copies, verbose, pretend_run, exit_on_failure):
    for obj in internal_copies:
        src_obj = paths.join_paths(tmp_dir, obj["from"])
        dest_obj = paths.join_paths(tmp_dir, obj["to"])
        if obj["from"].startswith("AppImageTool"):
            src_obj = paths.join_paths(environment.get_tools_root_dir(), obj["from"])
        success = filebulk.smart_copy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy AppImage file '%s' to '%s'" % (src_obj, dest_obj))
            return False
    return True

# Create each internal symlink relative to the AppImage directory; False at the first failure
def _symlink_appimage_objects(appimage_dir, internal_symlinks, verbose, pretend_run, exit_on_failure):
    for obj in internal_symlinks:
        src_obj = obj["from"]
        dest_obj = obj["to"]
        success = fileops.create_symlink(
            src = src_obj,
            dest = dest_obj,
            cwd = appimage_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to symlink AppImage object '%s' to '%s'" % (src_obj, dest_obj))
            return False
    return True
