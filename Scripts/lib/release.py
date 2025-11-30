# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import environment
import archive
import programs
import webpage
import network
import locker

# Setup stored release
def SetupStoredRelease(
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
    potential_archives = system.BuildFileList(archive_dir)
    if len(potential_archives) == 0:
        system.LogError("No available archives found in '%s'" % archive_dir)
        return False

    # Select archive file
    selected_archive = ""
    if isinstance(preferred_archive, str) and len(preferred_archive) > 0:
        for archive_path in potential_archives:
            if preferred_archive in system.GetFilenameFile(archive_path):
                selected_archive = archive_path
                break
    elif use_first_found:
        selected_archive = potential_archives[0]
    elif use_last_found:
        selected_archive = potential_archives[-1]
    if not os.path.exists(selected_archive):
        system.LogError("No archive could be selected")
        return False

    # Setup selected archive
    return SetupGeneralRelease(
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
def SetupGeneralRelease(
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        system.LogError("Unable to create temporary directory")
        return False

    # Get archive info
    archive_dir = system.GetFilenameDirectory(archive_file)
    archive_basename = system.GetFilenameBasename(archive_file)
    archive_extension = system.GetFilenameExtension(archive_file)
    archive_filename = system.GetFilenameFile(archive_file)
    archive_is_zip = archive.IsZipArchive(archive_file)
    archive_is_7z = archive.Is7zArchive(archive_file)
    archive_is_tarball = archive.IsTarballArchive(archive_file)
    archive_is_exe = archive.IsExeArchive(archive_file)
    archive_is_appimage = archive.IsAppImageArchive(archive_file)

    # Create install dir if necessary
    success = system.MakeDirectory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to create install directory %s" % install_dir)
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
            appimage_file = system.JoinPaths(tmp_dir_result, install_name + ".AppImage")

            # Copy app image
            success = system.SmartCopy(
                src = archive_file,
                dest = appimage_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to copy app image")
                return False

            # Mark app images as executable
            success = system.MarkAsExecutable(
                src = appimage_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to mark app image as executable")
                return False

            # Set install files
            install_files = [system.GetFilenameFile(appimage_file)]

        # Other formats
        else:

            # Set search dir to match that of the archive
            search_dir = archive_dir

    ####################################
    # Archive
    ####################################
    elif release_type == config.ReleaseType.ARCHIVE:

        # Extract archive
        success = archive.ExtractArchive(
            archive_file = archive_file,
            extract_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to extract downloaded release archive %s" % archive_file)
            return False

    ####################################
    # Unknown
    ####################################
    else:
        system.LogError("Unknown release type, please specify it")
        return False

    # Further refine search dir if we are looking for a particular file
    if isinstance(search_file, str) and len(search_file):
        for file in system.BuildFileList(search_dir):
            current_dir = system.GetFilenameDirectory(file)
            current_basefile = system.GetFilenameFile(file)
            if file.endswith(search_file):
                search_dir = current_dir
                break

    # Copy release files
    if isinstance(install_files, list) and len(install_files):
        for install_file in install_files:
            install_file_src = os.path.abspath(system.JoinPaths(search_dir, install_file))
            install_file_dest = system.JoinPaths(install_dir, install_file)
            success = system.SmartCopy(
                src = install_file_src,
                dest = install_file_dest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to copy install file %s" % install_file)
                return False
    else:
        success = system.CopyContents(
            src = search_dir,
            dest = install_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to copy install files from %s" % search_dir)
            return False

    # Chmod files
    if isinstance(chmod_files, list) and len(chmod_files):
        for filename in system.BuildFileList(install_dir):
            for chmod_entry in chmod_files:
                chmod_file = system.NormalizeFilePath(chmod_entry["file"])
                chmod_perms = chmod_entry["perms"]
                if filename.endswith(chmod_file):
                    success = system.ChmodFileOrDirectory(
                        src = filename,
                        perms = chmod_perms,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        system.LogError("Unable to update permissions for %s" % filename)
                        return False

    # Rename files
    if isinstance(rename_files, list) and len(rename_files):
        for filename in system.BuildFileList(install_dir):
            filename_dir = system.GetFilenameDirectory(filename)
            filename_file = system.GetFilenameFile(filename)
            for rename_entry in rename_files:
                rename_from = rename_entry["from"]
                rename_to = rename_entry["to"]
                rename_ratio = rename_entry["ratio"]
                if system.GetStringSimilarityRatio(rename_from, filename_file) > rename_ratio:
                    success = system.SmartMove(
                        src = filename,
                        dest = system.JoinPaths(filename_dir, rename_to),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        system.LogError("Unable to rename file %s" % filename)
                        return False

    # Backup files
    if system.IsPathValid(backups_dir):
        sucess = locker.BackupFiles(
            src = archive_file,
            dest = system.JoinPaths(backups_dir, archive_filename),
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to backup files")
            return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return system.DoesDirectoryContainFiles(install_dir)

# Download general release
def DownloadGeneralRelease(
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
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        system.LogError("Unable to create temporary directory")
        return False

    # Get archive info
    archive_basename = system.GetFilenameBasename(archive_url)
    archive_extension = system.GetFilenameExtension(archive_url)
    archive_filename = system.GetFilenameFile(archive_url)
    archive_file = system.JoinPaths(tmp_dir_result, archive_filename)

    # Download release
    success = network.DownloadUrl(
        url = archive_url,
        output_dir = tmp_dir_result,
        output_file = archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to download release from '%s'" % archive_url)
        return False

    # Setup release
    success = SetupGeneralRelease(
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
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Download github release
def DownloadGithubRelease(
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
    release_json_list = network.GetRemoteJson(
        url = github_url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not release_json_list:
        system.LogError("Unable to find github release information from '%s'" % github_url)
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
        system.LogError("Unable to find any release from '%s' matching start='%s' and end='%s'" % (github_url, starts_with, ends_with))
        return False

    # Download release
    return DownloadGeneralRelease(
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
def DownloadWebpageRelease(
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
    archive_url = webpage.GetMatchingUrl(
        url = webpage_url,
        base_url = webpage_base_url,
        starts_with = starts_with,
        ends_with = ends_with,
        get_latest = get_latest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not archive_url:
        system.LogError("Unable to find any release from '%s' matching start='%s' and end='%s'" % (webpage_url, starts_with, ends_with))
        return False

    # Download release
    return DownloadGeneralRelease(
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

# Build AppImage from source
def BuildAppImageFromSource(
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find release url if necessary
    if len(webpage_url):
        release_url = webpage.GetMatchingUrl(
            url = webpage_url,
            base_url = webpage_base_url,
            starts_with = starts_with,
            ends_with = ends_with,
            get_latest = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not release_url:
            system.LogError("No release url could be found from webpage %s" % webpage_url)
            return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        system.LogError("Unable to create temporary directory")
        return False

    # Get directories
    appimage_dir = system.JoinPaths(tmp_dir_result, "AppImage")
    source_dir = system.JoinPaths(tmp_dir_result, "Source")
    download_dir = system.JoinPaths(tmp_dir_result, "Download")
    source_build_dir = source_dir
    if len(build_dir) > 0:
        source_build_dir = os.path.abspath(system.JoinPaths(source_dir, build_dir))

    # Make folders
    system.MakeDirectory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = source_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = appimage_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = download_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download sources
    if release_url.endswith(".git"):

        # Download git release
        success = network.DownloadGitUrl(
            url = release_url,
            output_dir = source_dir,
            clean = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to download release from '%s'" % release_url)
            return False
    else:

        # Get archive info
        archive_basename = system.GetFilenameBasename(release_url)
        archive_extension = system.GetFilenameExtension(release_url)
        archive_file = system.JoinPaths(download_dir, archive_basename + archive_extension)

        # Download source archive
        success = network.DownloadUrl(
            url = release_url,
            output_file = archive_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to download release from '%s'" % release_url)
            return False

        # Extract source archive
        success = archive.ExtractArchive(
            archive_file = archive_file,
            extract_dir = source_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to extract source archive")
            return False

    # Make build folder
    success = system.MakeDirectory(
        src = source_build_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to make build folder '%s'" % source_build_dir)
        return False

    # Build release
    code = command.RunReturncodeCommand(
        cmd = build_cmd,
        options = command.CreateCommandOptions(
            cwd = source_build_dir,
            is_shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Unable to build release")
        return False

    # Copy AppImage objects
    for obj in internal_copies:
        src_obj = system.JoinPaths(tmp_dir_result, obj["from"])
        dest_obj = system.JoinPaths(tmp_dir_result, obj["to"])
        if obj["from"].startswith("AppImageTool"):
            src_obj = system.JoinPaths(environment.GetToolsRootDir(), obj["from"])
        success = system.SmartCopy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to copy AppImage file '%s' to '%s'" % (src_obj, dest_obj))
            return False

    # Symlink AppImage objects
    for obj in internal_symlinks:
        src_obj = obj["from"]
        dest_obj = obj["to"]
        success = system.CreateSymlink(
            src = src_obj,
            dest = dest_obj,
            cwd = appimage_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to symlink AppImage object '%s' to '%s'" % (src_obj, dest_obj))
            return False

    # Build AppImage
    code = command.RunReturncodeCommand(
        cmd = [programs.GetToolProgram("AppImageTool"), appimage_dir],
        options = command.CreateCommandOptions(
            cwd = tmp_dir_result),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Unable to create AppImage from built release")
        return False

    # Find built release file
    built_file = None
    for path in system.BuildFileList(tmp_dir_result):
        if path.endswith(output_file):
            built_file = path
    if not built_file:
        system.LogError("No built files could be found")
        return False

    # Get final file
    final_file = install_name + ".AppImage"

    # Copy release file
    success = system.SmartCopy(
        src = built_file,
        dest = system.JoinPaths(install_dir, final_file),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to copy release files")
        return False

    # Copy other objects
    for obj in external_copies:
        src_obj = system.JoinPaths(tmp_dir_result, obj["from"])
        dest_obj = system.JoinPaths(install_dir, obj["to"])
        success = system.SmartCopy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to copy other files")
            return False

    # Backup files
    if system.IsPathValid(backups_dir):
        sucess = locker.BackupFiles(
            src = built_file,
            dest = system.JoinPaths(backups_dir, final_file),
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to backup files")
            return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(system.JoinPaths(install_dir, final_file))
