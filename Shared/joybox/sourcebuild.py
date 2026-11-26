# Building releases from source: fetching the source, applying patches,
# running the build and installing what it produced.

# Imports
import os

# Local imports
from joybox import archive
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
        patch_file, patch_content = resolve_patch_entry(
            patch_entry = patch_entry,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if patch_file is None:
            logger.log_error("Unable to read patch file '%s'" % patch_entry.get("path"))
            return False
        if not patch_content:
            logger.log_error("Patch entry %d has no content" % patch_index)
            return False
        if not patch_file:
            patch_file = "source_patch_%d" % patch_index

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

# Build from source
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
    if webpage_url:
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
            return None

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        logger.log_error("Unable to create temporary directory")
        return None

    build_succeeded = False
    try:

        # Get directories
        source_base_dir = paths.join_paths(tmp_dir_result, "Source")
        download_dir = paths.join_paths(tmp_dir_result, "Download")

        # Make folders
        for folder in [source_base_dir, download_dir]:
            success = fileops.make_directory(
                src = folder,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to make folder '%s'" % folder)
                return None

        # Download sources
        if not release_url:
            logger.log_error("No release url was given")
            return None
        if release_url.rstrip("/").endswith(".git"):

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
        else:

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

        # Get build directory
        source_build_dir = source_dir
        if build_dir:
            source_build_dir = os.path.abspath(paths.join_paths(source_dir, build_dir))

        # Apply source patches
        success = apply_source_patches(
            source_patches = source_patches,
            source_dir = source_dir,
            patch_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Make build folder
        success = fileops.make_directory(
            src = source_build_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to make build folder '%s'" % source_build_dir)
            return None

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
            return None

        # Return build info
        build_succeeded = True
        return {
            "tmp_dir": tmp_dir_result,
            "source_dir": source_dir,
            "build_dir": source_build_dir
        }
    finally:
        if not build_succeeded:
            release.remove_temporary_directory(tmp_dir_result, verbose = verbose, pretend_run = pretend_run)

# Build binary from source
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
    build_info = build_from_source(
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
    if not build_info:
        return False

    # Get build result
    tmp_dir = build_info["tmp_dir"]
    try:
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
        built_file = None
        for path in paths.build_file_list(search_dir):
            if path.endswith(output_file):
                built_file = path
        if not built_file and pretend_run:
            built_file = paths.join_paths(search_dir, output_file)
        if not built_file:
            logger.log_error("No built files could be found")
            return False

        # Get final file for backup
        if output_file.startswith("."):
            final_file = install_name + output_file
        else:
            final_file = install_name + paths.get_filename_extension(output_file)

        # Check if output is an archive that needs extraction
        is_archive = archive.is_archive(built_file)
        if is_archive and search_file:

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
        else:
            # Copy release file directly
            success = filebulk.smart_copy(
                src = built_file,
                dest = paths.join_paths(install_dir, final_file),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to copy release files")
                return False

        # Copy other objects
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

        # Backup files
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

        # Check result
        if pretend_run:
            return True
        return paths.does_directory_contain_files(install_dir)
    finally:
        release.remove_temporary_directory(tmp_dir, verbose = verbose, pretend_run = pretend_run)

# Build AppImage from source
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
    build_info = build_from_source(
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
    if not build_info:
        return False

    # Get build result
    tmp_dir = build_info["tmp_dir"]
    try:
        appimage_dir = paths.join_paths(tmp_dir, "AppImage")

        # Make folders
        for folder in [install_dir, appimage_dir]:
            success = fileops.make_directory(
                src = folder,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to make folder '%s'" % folder)
                return False

        # Copy AppImage objects
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

        # Symlink AppImage objects
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

        # Find built release file
        built_file = None
        for path in paths.build_file_list(tmp_dir):
            if path.endswith(output_file):
                built_file = path
        if not built_file and pretend_run:
            built_file = paths.join_paths(tmp_dir, output_file)
        if not built_file:
            logger.log_error("No built files could be found")
            return False

        # Get final file
        final_file = install_name + ".AppImage"

        # Copy release file
        success = filebulk.smart_copy(
            src = built_file,
            dest = paths.join_paths(install_dir, final_file),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy release files")
            return False

        # Copy other objects
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

        # Backup files
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

        # Check result
        if pretend_run:
            return True
        return os.path.exists(paths.join_paths(install_dir, final_file))
    finally:
        release.remove_temporary_directory(tmp_dir, verbose = verbose, pretend_run = pretend_run)
