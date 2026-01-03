# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import logger
import environment
import fileops
import archive
import programs
import strings
import webpage
import network
import paths
import locker

# Setup stored release
def setup_stored_release(
    archive_dir,
    install_name,
    install_dir,
    preferred_archive = None,
    use_first_found = False,
    use_last_found = True,
    search_file = None,
    install_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get list of potential archives
    potential_archives = paths.build_file_list(archive_dir)
    if len(potential_archives) == 0:
        logger.log_error("No available archives found in '%s'" % archive_dir)
        return False

    # Select archive file
    selected_archive = ""
    if isinstance(preferred_archive, str) and len(preferred_archive) > 0:
        for archive_path in potential_archives:
            if preferred_archive in paths.get_filename_file(archive_path):
                selected_archive = archive_path
                break
    elif use_first_found:
        selected_archive = potential_archives[0]
    elif use_last_found:
        selected_archive = potential_archives[-1]
    if not os.path.exists(selected_archive):
        logger.log_error("No archive could be selected")
        return False

    # Setup selected archive
    return setup_general_release(
        archive_file = selected_archive,
        install_name = install_name,
        install_dir = install_dir,
        search_file = search_file,
        install_files = install_files,
        chmod_files = chmod_files,
        rename_files = rename_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Setup general release
def setup_general_release(
    archive_file,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        logger.log_error("Unable to create temporary directory")
        return False

    # Get archive info
    archive_dir = paths.get_filename_directory(archive_file)
    archive_basename = paths.get_filename_basename(archive_file)
    archive_extension = paths.get_filename_extension(archive_file)
    archive_filename = paths.get_filename_file(archive_file)
    archive_is_zip = archive.is_zip_archive(archive_file)
    archive_is_7z = archive.is_7z_archive(archive_file)
    archive_is_tarball = archive.is_tarball_archive(archive_file)
    archive_is_exe = archive.is_exe_archive(archive_file)
    archive_is_appimage = archive.is_appimage_archive(archive_file)

    # Create install dir if necessary
    success = fileops.make_directory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to create install directory %s" % install_dir)
        return False

    # Set initial search dir
    search_dir = tmp_dir_result

    # Guess the release type if none specified
    if not release_type:
        if archive_is_zip or archive_is_7z or archive_is_tarball:
            release_type = config.ReleaseType.ARCHIVE
        elif archive_is_exe or archive_is_appimage:
            release_type = config.ReleaseType.PROGRAM

    ####################################
    # Standalone program
    ####################################
    if release_type == config.ReleaseType.PROGRAM:

        # AppImage format
        if archive_extension.lower() == ".appimage":

            # Get new appimage file
            appimage_file = paths.join_paths(tmp_dir_result, install_name + ".AppImage")

            # Copy app image
            success = fileops.smart_copy(
                src = archive_file,
                dest = appimage_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to copy app image")
                return False

            # Mark app images as executable
            success = fileops.mark_as_executable(
                src = appimage_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to mark app image as executable")
                return False

            # Set install files
            install_files = [paths.get_filename_file(appimage_file)]

        # Other formats
        else:

            # Set search dir to match that of the archive
            search_dir = archive_dir

    ####################################
    # Archive
    ####################################
    elif release_type == config.ReleaseType.ARCHIVE:

        # Extract archive
        success = archive.extract_archive(
            archive_file = archive_file,
            extract_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to extract downloaded release archive %s" % archive_file)
            return False

    ####################################
    # Unknown
    ####################################
    else:
        logger.log_error("Unknown release type, please specify it")
        return False

    # Further refine search dir if we are looking for a particular file
    if isinstance(search_file, str) and len(search_file):
        for file in paths.build_file_list(search_dir):
            current_dir = paths.get_filename_directory(file)
            current_basefile = paths.get_filename_file(file)
            if file.endswith(search_file):
                search_dir = current_dir
                break

    # Copy release files
    if isinstance(install_files, list) and len(install_files):
        for install_file in install_files:
            install_file_src = os.path.abspath(paths.join_paths(search_dir, install_file))
            install_file_dest = paths.join_paths(install_dir, install_file)
            success = fileops.smart_copy(
                src = install_file_src,
                dest = install_file_dest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to copy install file %s" % install_file)
                return False
    else:
        success = fileops.copy_contents(
            src = search_dir,
            dest = install_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy install files from %s" % search_dir)
            return False

    # Chmod files
    if isinstance(chmod_files, list) and len(chmod_files):
        for filename in paths.build_file_list(install_dir):
            for chmod_entry in chmod_files:
                chmod_file = paths.normalize_file_path(chmod_entry["file"])
                chmod_perms = chmod_entry["perms"]
                if filename.endswith(chmod_file):
                    success = fileops.chmod_file_or_directory(
                        src = filename,
                        perms = chmod_perms,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        logger.log_error("Unable to update permissions for %s" % filename)
                        return False

    # Rename files
    if isinstance(rename_files, list) and len(rename_files):
        for filename in paths.build_file_list(install_dir):
            filename_dir = paths.get_filename_directory(filename)
            filename_file = paths.get_filename_file(filename)
            for rename_entry in rename_files:
                rename_from = rename_entry["from"]
                rename_to = rename_entry["to"]
                rename_ratio = rename_entry["ratio"]
                if strings.get_string_similarity_ratio(rename_from, filename_file) > rename_ratio:
                    success = fileops.smart_move(
                        src = filename,
                        dest = paths.join_paths(filename_dir, rename_to),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        logger.log_error("Unable to rename file %s" % filename)
                        return False

    # Backup files
    if paths.is_path_valid(backups_dir):
        success = locker.backup_files(
            src = archive_file,
            dest = paths.join_paths(backups_dir, archive_filename),
            locker_type = locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to backup files")
            return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return paths.does_directory_contain_files(install_dir)

# Download general release
def download_general_release(
    archive_url,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        logger.log_error("Unable to create temporary directory")
        return False

    # Get archive info
    archive_basename = paths.get_filename_basename(archive_url)
    archive_extension = paths.get_filename_extension(archive_url)
    archive_filename = paths.get_filename_file(archive_url)
    archive_file = paths.join_paths(tmp_dir_result, archive_filename)

    # Download release
    success = network.download_url(
        url = archive_url,
        output_dir = tmp_dir_result,
        output_file = archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download release from '%s'" % archive_url)
        return False

    # Setup release
    success = setup_general_release(
        archive_file = archive_file,
        install_name = install_name,
        install_dir = install_dir,
        search_file = search_file,
        backups_dir = backups_dir,
        install_files = install_files,
        chmod_files = chmod_files,
        rename_files = rename_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Download github release
def download_github_release(
    github_user,
    github_repo,
    starts_with,
    ends_with,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    get_latest = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get github url
    github_url = "https://api.github.com/repos/%s/%s/releases" % (github_user, github_repo)
    if get_latest:
        github_url = "https://api.github.com/repos/%s/%s/releases/latest" % (github_user, github_repo)

    # Get release json list
    release_json_list = network.get_remote_json(
        url = github_url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not release_json_list:
        logger.log_error("Unable to find github release information from '%s'" % github_url)
        return False
    if not isinstance(release_json_list, list):
        release_json_list = [release_json_list]

    # Find matching archive url
    archive_url = ""
    for release_json in release_json_list:
        if len(archive_url):
            break
        if "assets" in release_json:
            for releases_asset in release_json["assets"]:
                browser_download_file = releases_asset["name"]
                browser_download_url = releases_asset["browser_download_url"]
                match_found = False
                if len(starts_with) and len(ends_with):
                    match_found = browser_download_file.startswith(starts_with) and browser_download_file.endswith(ends_with)
                elif len(starts_with):
                    match_found = browser_download_file.startswith(starts_with)
                elif len(ends_with):
                    match_found = browser_download_file.endswith(ends_with)
                if match_found:
                    archive_url = browser_download_url
                    break

    # Did not find any matching release
    if not archive_url:
        logger.log_error("Unable to find any release from '%s' matching start='%s' and end='%s'" % (github_url, starts_with, ends_with))
        return False

    # Download release
    return download_general_release(
        archive_url = archive_url,
        install_name = install_name,
        install_dir = install_dir,
        search_file = search_file,
        backups_dir = backups_dir,
        install_files = install_files,
        chmod_files = chmod_files,
        rename_files = rename_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download webpage release
def download_webpage_release(
    webpage_url,
    webpage_base_url,
    starts_with,
    ends_with,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    get_latest = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get archive url
    archive_url = webpage.get_matching_url(
        url = webpage_url,
        base_url = webpage_base_url,
        starts_with = starts_with,
        ends_with = ends_with,
        get_latest = get_latest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not archive_url:
        logger.log_error("Unable to find any release from '%s' matching start='%s' and end='%s'" % (webpage_url, starts_with, ends_with))
        return False

    # Download release
    return download_general_release(
        archive_url = archive_url,
        install_name = install_name,
        install_dir = install_dir,
        search_file = search_file,
        backups_dir = backups_dir,
        install_files = install_files,
        chmod_files = chmod_files,
        rename_files = rename_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build from source
def build_from_source(
    release_url = "",
    webpage_url = "",
    webpage_base_url = "",
    starts_with = "",
    ends_with = "",
    build_cmd = "",
    build_dir = "",
    source_patches = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find release url if necessary
    if len(webpage_url):
        release_url = webpage.get_matching_url(
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

    # Get directories
    source_base_dir = paths.join_paths(tmp_dir_result, "Source")
    download_dir = paths.join_paths(tmp_dir_result, "Download")

    # Make folders
    fileops.make_directory(
        src = source_base_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    fileops.make_directory(
        src = download_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download sources
    if release_url.endswith(".git"):

        # Get repo name
        repo_name = paths.get_filename_basename(release_url.rstrip("/"))
        source_dir = paths.join_paths(source_base_dir, repo_name)

        # Download git release
        success = network.download_git_url(
            url = release_url,
            output_dir = source_dir,
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
    if len(build_dir) > 0:
        source_build_dir = os.path.abspath(paths.join_paths(source_dir, build_dir))

    # Apply source patches
    if isinstance(source_patches, list) and len(source_patches):
        for patch_entry in source_patches:
            patch_file = patch_entry.get("file", "")
            patch_content = patch_entry.get("content", "")
            patch_path = patch_entry.get("path", "")

            # Load patch content from file if path is provided
            if len(patch_path) and os.path.isfile(patch_path):
                with open(patch_path, "r") as f:
                    patch_content = f.read()
                if not patch_file:
                    patch_file = os.path.basename(patch_path)

            if len(patch_file) and len(patch_content):

                # Write patch to temp file
                patch_temp_file = paths.join_paths(tmp_dir_result, patch_file if patch_file.endswith(".patch") else patch_file + ".patch")
                success = fileops.touch_file(
                    src = patch_temp_file,
                    contents = patch_content,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    logger.log_error("Unable to write patch file '%s'" % patch_temp_file)
                    return None

                # Apply patch with git apply
                code = command.run_returncode_command(
                    cmd = [
                        programs.get_tool_program("Git"),
                        "apply",
                        patch_temp_file
                    ],
                    options = command.create_command_options(
                        cwd = source_dir),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if code != 0:
                    logger.log_error("Unable to apply patch '%s'" % patch_file)
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
        options = command.create_command_options(
            cwd = source_build_dir,
            is_shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to build release")
        return None

    # Return build info
    return {
        "tmp_dir": tmp_dir_result,
        "source_dir": source_dir,
        "build_dir": source_build_dir
    }

# Build binary from source
def build_binary_from_source(
    release_url = "",
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
    external_copies = [],
    source_patches = [],
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build from source
    build_info = build_from_source(
        release_url = release_url,
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
    source_dir = build_info["source_dir"]

    # Make install folder
    fileops.make_directory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Determine search directory for built files
    search_dir = tmp_dir
    if len(output_dir) > 0:
        search_dir = paths.join_paths(source_dir, output_dir)

    # Find built release file
    built_file = None
    for path in paths.build_file_list(search_dir):
        if path.endswith(output_file):
            built_file = path
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
    if is_archive and len(search_file):

        # Extract archive and install contents
        extract_dir = paths.join_paths(tmp_dir, "Extract")
        fileops.make_directory(
            src = extract_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
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
        success = fileops.copy_contents(
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
        success = fileops.smart_copy(
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
        success = fileops.smart_copy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy other files")
            return False

    # Backup files
    if paths.is_path_valid(backups_dir):
        success = locker.backup_files(
            src = built_file,
            dest = paths.join_paths(backups_dir, final_file),
            locker_type = locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to backup files")
            return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return paths.does_directory_contain_files(install_dir)

# Build AppImage from source
def build_appimage_from_source(
    release_url = "",
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
    internal_copies = [],
    internal_symlinks = [],
    external_copies = [],
    source_patches = [],
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build from source
    build_info = build_from_source(
        release_url = release_url,
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
    appimage_dir = paths.join_paths(tmp_dir, "AppImage")

    # Make folders
    fileops.make_directory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    fileops.make_directory(
        src = appimage_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy AppImage objects
    for obj in internal_copies:
        src_obj = paths.join_paths(tmp_dir, obj["from"])
        dest_obj = paths.join_paths(tmp_dir, obj["to"])
        if obj["from"].startswith("AppImageTool"):
            src_obj = paths.join_paths(environment.get_tools_root_dir(), obj["from"])
        success = fileops.smart_copy(
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
        options = command.create_command_options(
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
    if not built_file:
        logger.log_error("No built files could be found")
        return False

    # Get final file
    final_file = install_name + ".AppImage"

    # Copy release file
    success = fileops.smart_copy(
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
        success = fileops.smart_copy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy other files")
            return False

    # Backup files
    if paths.is_path_valid(backups_dir):
        success = locker.backup_files(
            src = built_file,
            dest = paths.join_paths(backups_dir, final_file),
            locker_type = locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to backup files")
            return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(paths.join_paths(install_dir, final_file))
