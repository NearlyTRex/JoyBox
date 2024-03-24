# Imports
import os, os.path
import sys

# Local imports
import config
import command
import sandbox
import system
import environment
import archive
import programs
import installer
import webpage
import registry
import network

# Setup general release
def SetupGeneralRelease(
    archive_file,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    registry_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    verbose = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        system.LogError("Unable to create temporary directory")
        return False

    # Get archive info
    archive_dir = system.GetFilenameDirectory(archive_file)
    archive_basename = system.GetFilenameBasename(archive_file)
    archive_extension = system.GetFilenameExtension(archive_file)
    archive_filename = system.GetFilenameFile(archive_file)

    # Create install dir if necessary
    success = system.MakeDirectory(install_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to create install directory %s" % install_dir)
        return False

    # Set initial search dir
    search_dir = tmp_dir_result

    ####################################
    # Standalone program
    ####################################
    if release_type == config.release_type_program:

        # AppImage format
        if archive_extension.lower() == ".appimage":

            # Get new appimage file
            appimage_file = os.path.join(tmp_dir_result, install_name + ".AppImage")

            # Copy app image
            success = system.SmartCopy(
                src = archive_file,
                dest = appimage_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to copy app image")
                return False

            # Mark app images as executable
            success = system.MarkAsExecutable(
                src = appimage_file,
                verbose = verbose,
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
    # Executable installer
    ####################################
    elif release_type == config.release_type_installer:

        # Exe installer
        if archive_extension == ".exe":

            # Check if installer should be run via wine/sandboxie
            should_run_via_wine = environment.IsWinePlatform()
            should_run_via_sandboxie = environment.IsSandboxiePlatform()

            # Get real and virtual install paths
            real_install_path = os.path.join(tmp_dir_result, "install")
            virtual_install_path = sandbox.TranslateRealPathToVirtualPath(
                path = real_install_path,
                prefix_dir = prefix_dir,
                prefix_name = prefix_name,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie)

            # Create real install path
            system.MakeDirectory(real_install_path, verbose = verbose, exit_on_failure = exit_on_failure)

            # Get installer setup command
            installer_setup_cmd = installer.GetInstallerSetupCommand(
                installer_file = archive_file,
                installer_type = installer_type,
                install_dir = virtual_install_path,
                silent_install = False)
            if not installer_setup_cmd:
                system.LogError("Unable to get installer setup command")
                return False

            # Create prefix
            sandbox.CreateBasicPrefix(
                prefix_dir = prefix_dir,
                prefix_name = prefix_name,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

            # Run installer
            code = command.RunBlockingCommand(
                cmd = installer_setup_cmd,
                options = command.CommandOptions(
                    cwd = real_install_path,
                    prefix_dir = prefix_dir,
                    prefix_name = prefix_name,
                    is_wine_prefix = should_run_via_wine,
                    is_sandboxie_prefix = should_run_via_sandboxie,
                    force_prefix = True,
                    blocking_processes = [archive_file]),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if code != 0:
                system.LogError("Error occurred running the setup installer")
                return False

            # Set search directory to best location for installed files
            search_dir = prefix_dir
            if installer_type != config.installer_type_unknown:
                search_dir = real_install_path

    ####################################
    # Archive
    ####################################
    elif release_type == config.release_type_archive:

        # Extract archive
        success = archive.ExtractArchive(
            archive_file = archive_file,
            extract_dir = tmp_dir_result,
            verbose = verbose,
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
            if current_basefile.endswith(search_file):
                search_dir = current_dir
                break

    # Copy release files
    if isinstance(install_files, list) and len(install_files):
        for install_file in install_files:
            install_file_src = os.path.abspath(os.path.join(search_dir, install_file))
            install_file_dest = os.path.join(install_dir, install_file)
            success = system.SmartCopy(
                src = install_file_src,
                dest = install_file_dest,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to copy install file %s" % install_file)
                return False
    else:
        success = system.CopyContents(
            src = search_dir,
            dest = install_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to copy install files from %s" % search_dir)
            return False

    # Registry files
    if isinstance(registry_files, list) and len(registry_files):
        for registry_file in registry_files:
            success = registry.ImportRegistryFile(
                registry_file = registry_file,
                prefix_dir = prefix_dir,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to import registry file %s" % registry_file)
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
                        exit_on_failure = exit_on_failure)
                    if not success:
                        system.LogError("Unable to update permissions for %s" % filename)
                        return False

    # Rename files
    if isinstance(rename_files, list) and len(rename_files):
        for filename in system.BuildFileList(install_dir):
            for rename_entry in rename_files:
                rename_from = rename_entry["from"]
                rename_to = rename_entry["to"]
                if filename.endswith(rename_from):
                    success = system.SmartMove(
                        src = filename,
                        dest = filename.replace(rename_from, rename_to),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        system.LogError("Unable to rename file %s" % filename)
                        return False

    # Backup archive
    if system.IsPathValid(backups_dir):
        backup_file = os.path.join(backups_dir, archive_filename)
        if archive_extension == "":
            backup_file = os.path.join(backups_dir, archive_basename + ".zip")
        system.SmartCopy(
            src = archive_file,
            dest = backup_file,
            skip_identical = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Check result
    return system.DoesDirectoryContainFiles(install_dir)

# Download general release
def DownloadGeneralRelease(
    archive_url,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    registry_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    release_type = None,
    verbose = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        system.LogError("Unable to create temporary directory")
        return False

    # Get archive info
    archive_basename = system.GetFilenameBasename(archive_url)
    archive_extension = system.GetFilenameExtension(archive_url)
    archive_filename = system.GetFilenameFile(archive_url)
    archive_file = os.path.join(tmp_dir_result, archive_filename)

    # Download release
    if not network.DownloadUrl(url=archive_url, output_dir=tmp_dir_result, output_file=archive_file):
        system.LogError("Unable to download release from '%s'" % archive_url)
        return False

    # Setup release
    success = SetupGeneralRelease(
        archive_file = archive_file,
        install_name = install_name,
        install_dir = install_dir,
        search_file = search_file,
        backups_dir = backups_dir,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        install_files = install_files,
        registry_files = registry_files,
        chmod_files = chmod_files,
        rename_files = rename_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)
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
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    chmod_files = [],
    installer_type = None,
    release_type = None,
    get_latest = False,
    verbose = False,
    exit_on_failure = False):

    # Get github url
    github_url = "https://api.github.com/repos/%s/%s/releases" % (github_user, github_repo)
    if get_latest:
        github_url = "https://api.github.com/repos/%s/%s/releases/latest" % (github_user, github_repo)

    # Get release json list
    release_json_list = network.GetRemoteJson(
        url = github_url,
        headers = {"Accept": "application/json"},
        verbose = verbose,
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
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        install_files = install_files,
        chmod_files = chmod_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Download webpage release
def DownloadWebpageRelease(
    webpage_url,
    starts_with,
    ends_with,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    chmod_files = [],
    installer_type = None,
    release_type = None,
    get_latest = False,
    verbose = False,
    exit_on_failure = False):

    # Get archive url
    archive_url = webpage.GetMatchingUrl(
        url = webpage_url,
        starts_with = starts_with,
        ends_with = ends_with,
        get_latest = get_latest,
        verbose = verbose)
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
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        install_files = install_files,
        chmod_files = chmod_files,
        installer_type = installer_type,
        release_type = release_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Build appimage from source
def BuildAppImageFromSource(
    release_url = "",
    webpage_url = "",
    starts_with = "",
    ends_with = "",
    install_name = "",
    install_dir = "",
    backups_dir = "",
    build_cmd = "",
    build_dir = "",
    internal_copies = [],
    internal_symlinks = [],
    external_copies = [],
    verbose = False,
    exit_on_failure = False):

    # Only works on linux systems
    if not environment.IsLinuxPlatform():
        system.LogError("Building app images only works on linux")
        return False

    # Check params
    system.AssertIsString(release_url, "release_url")
    system.AssertIsString(webpage_url, "webpage_url")
    system.AssertIsString(install_name, "install_name")
    system.AssertIsString(install_dir, "install_dir")
    system.AssertIsList(build_cmd, "build_cmd")
    system.AssertIsString(build_dir, "build_dir")

    # Find release url if necessary
    if len(webpage_url):
        release_url = webpage.GetMatchingUrl(
            url = webpage_url,
            starts_with = starts_with,
            ends_with = ends_with,
            get_latest = True,
            verbose = verbose)
        if not release_url:
            system.LogError("No release url could be found from webpage %s" % webpage_url)
            return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        system.LogError("Unable to create temporary directory")
        return False

    # Get directories
    appimage_dir = os.path.join(tmp_dir_result, "AppImage")
    source_dir = os.path.join(tmp_dir_result, "Source")
    download_dir = os.path.join(tmp_dir_result, "Download")
    source_build_dir = source_dir
    if len(build_dir) > 0:
        source_build_dir = os.path.abspath(os.path.join(source_dir, build_dir))

    # Make folders
    system.MakeDirectory(install_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(source_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(appimage_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(download_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Download sources
    if release_url.endswith(".git"):

        # Download git release
        success = network.DownloadGitUrl(
            url = release_url,
            output_dir = source_dir,
            clean = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to download release from '%s'" % release_url)
            return False
    else:

        # Get archive info
        archive_basename = system.GetFilenameBasename(release_url)
        archive_extension = system.GetFilenameExtension(release_url)
        archive_file = os.path.join(download_dir, archive_basename + archive_extension)

        # Download source archive
        success = network.DownloadUrl(url = release_url, output_file = archive_file)
        if not success:
            system.LogError("Unable to download release from '%s'" % release_url)
            return False

        # Extract source archive
        success = archive.ExtractArchive(
            archive_file = archive_file,
            extract_dir = source_dir,
            verbose = verbose)
        if not success:
            system.LogError("Unable to extract source archive")
            return False

    # Make build folder
    system.MakeDirectory(source_build_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Build release
    code = command.RunBlockingCommand(
        cmd = build_cmd,
        options = command.CommandOptions(
            cwd = source_build_dir,
            shell = True),
        verbose = verbose)
    if code != 0:
        system.LogError("Unable to build release")
        return False

    # Copy objects
    for obj in internal_copies:
        src_obj = os.path.join(tmp_dir_result, obj["from"])
        dest_obj = os.path.join(tmp_dir_result, obj["to"])
        if obj["from"].startswith("AppImageTool"):
            src_obj = os.path.join(environment.GetToolsRootDir(), obj["from"])
        system.MakeDirectory(
            dir = os.path.dirname(dest_obj),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.SmartCopy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Symlink objects
    for obj in internal_symlinks:
        src_obj = obj["from"]
        dest_obj = obj["to"]
        system.CreateSymlink(
            src = src_obj,
            dest = dest_obj,
            cwd = appimage_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Build appimage
    code = command.RunBlockingCommand(
        cmd = [programs.GetToolProgram("AppImageTool"), appimage_dir],
        options = command.CommandOptions(
            cwd = tmp_dir_result),
        verbose = verbose)
    if code != 0:
        system.LogError("Unable to create AppImage from built release")
        return False

    # Get output appimages
    appimage_files = system.BuildFileListByExtensions(tmp_dir_result, extensions = [".AppImage"])
    if len(appimage_files) == 0:
        system.LogError("No AppImages could be found")
        return False

    # Copy appimage
    system.SmartCopy(
        src = appimage_files[0],
        dest = os.path.join(install_dir, install_name + ".AppImage"),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Copy other objects
    for obj in external_copies:
        src_obj = os.path.join(tmp_dir_result, obj["from"])
        dest_obj = os.path.join(install_dir, obj["to"])
        system.SmartCopy(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Backup archive
    if system.IsPathValid(backups_dir):
        system.SmartCopy(
            src = appimage_files[0],
            dest = os.path.join(backups_dir, install_name + ".AppImage"),
            skip_identical = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Check result
    return os.path.exists(os.path.join(install_dir, install_name + ".AppImage"))
