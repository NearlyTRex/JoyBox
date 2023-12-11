# Imports
import os, os.path
import sys
import getpass
import time

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
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

# Check if url is reachable
def IsUrlReachable(url):
    try:
        import requests
        get = requests.get(url)
        if get.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        return False

# Get remote json
def GetRemoteJson(url):
    try:
        import requests
        get = requests.get(url, headers={"Accept": "application/json"})
        if get.status_code == 200:
            return get.json()
        return None
    except Exception as e:
        return None

# Download url to local dir
def DownloadUrl(url, output_dir = None, output_file = None, verbose = False, exit_on_failure = False):

    # Check download tools
    has_wget = command.IsRunnableCommand(config.default_wget_exe, config.default_system_tools_dirs)
    has_curl = command.IsRunnableCommand(config.default_curl_exe, config.default_system_tools_dirs)
    wget_path = command.GetRunnableCommandPath(config.default_wget_exe, config.default_system_tools_dirs)
    curl_path = command.GetRunnableCommandPath(config.default_curl_exe, config.default_system_tools_dirs)

    # Get download command
    download_cmd = None
    download_tool = None
    if has_wget:
        download_tool = wget_path
        download_cmd = [wget_path]
        if output_dir:
            download_cmd += ["-P", output_dir]
        elif output_file:
            download_cmd += ["-O", output_file]
        download_cmd += [url]
    elif has_curl:
        download_tool = curl_path
        download_cmd = [curl_path, "-L"]
        if output_dir:
            download_cmd += ["--output-dir", output_dir, "-O"]
        elif output_file:
            download_cmd += ["--output", output_file]
        download_cmd += [url]
    if not download_cmd:
        return False

    # Create output directory
    if output_dir:
        system.MakeDirectory(output_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Run download command
    command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            allow_processing = environment.IsWinePlatform(),
            blocking_processes = [download_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check result
    if output_dir:
        for obj in system.GetDirectoryContents(output_dir):
            obj_path = os.path.join(output_dir, obj)
            if os.path.isfile(obj_path) and obj.endswith(system.GetFilenameFile(url)):
                return True
    elif output_file:
        return os.path.isfile(output_file)
    return False

# Download git url
def DownloadGitUrl(url, output_dir, clean_first = False, verbose = False, exit_on_failure = False):

    # Clear output dir
    if clean_first:
        system.RemoveDirectoryContents(
            dir = output_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Check output dir
    if os.path.isdir(output_dir) and system.DoesDirectoryContainFiles(output_dir):
        return False

    # Get tool
    download_tool = None
    if command.IsRunnableCommand(config.default_git_exe, config.default_git_install_dirs):
        download_tool = command.GetRunnableCommandPath(config.default_git_exe, config.default_git_install_dirs)
    if not download_tool:
        return False

    # Get download command
    download_cmd = [
        download_tool,
        "clone",
        "--recursive",
        url,
        output_dir
    ]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            cwd = os.path.expanduser("~"),
            blocking_processes = [download_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)

# Determine if network share is mounted
def IsNetworkShareMounted(mount_dir, base_location, network_share):

    # Windows
    if environment.IsWindowsPlatform():
        return os.path.isdir(mount_dir) and not system.IsDirectoryEmpty(mount_dir)

    # Linux
    elif environment.IsLinuxPlatform():
        mount_lines = command.RunOutputCommand(
            cmd = ["mount"])
        for line in mount_lines.split("\n"):
            if line.startswith("//%s/%s" % (base_location, network_share)):
                if mount_dir in line:
                    return True
        return False

    # Network share was not mounted
    return False

# Mount network share
def MountNetworkShare(mount_dir, base_location, network_share, username, password, verbose = False, exit_on_failure = False):

    # Windows
    if environment.IsWindowsPlatform():

        # Check if already mounted
        if os.path.isdir(mount_dir):
            return True

        # Get mount command
        mount_cmd = [
            "net",
            "use",
            "%s:" % system.GetDirectoryDrive(mount_dir),
            "\\\\%s\\%s" % (base_location, network_share),
            "/USER:%s" % username,
            password
        ]

        # Run mount command
        command.RunCheckedCommand(
            cmd = mount_cmd,
            verbose = verbose)
        return True

    # Linux
    elif environment.IsLinuxPlatform():

        # Get mkdir command
        mkdir_cmd = [
            "sudo",
            "mkdir",
            "-p",
            mount_dir
        ]

        # Run mkdir command
        command.RunCheckedCommand(
            cmd = mkdir_cmd,
            verbose = verbose)

        # Check if already mounted
        if not system.IsDirectoryEmpty(mount_dir):
            return True

        # Get mount command
        mount_cmd = [
            "sudo",
            "mount",
            "-t", "cifs",
            "-o", "username=%s,password=%s,uid=%s,gid=%s" % (username, password, os.geteuid(), os.getegid()),
            "//%s/%s" % (base_location, network_share),
            "%s" % mount_dir
        ]

        # Run mount command
        command.RunCheckedCommand(
            cmd = mount_cmd,
            verbose = verbose)
        return True

    # Network share was not mounted
    return False

# Download general release
def DownloadGeneralRelease(
    archive_url,
    search_file,
    install_name,
    install_dir,
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    registry_files = [],
    chmod_files = [],
    rename_files = [],
    installer_type = None,
    is_installer = False,
    is_archive = False,
    verbose = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get archive info
    archive_basename = system.GetFilenameBasename(archive_url)
    archive_extension = system.GetFilenameExtension(archive_url)
    archive_filename = system.GetFilenameFile(archive_url)
    archive_file = os.path.join(tmp_dir_result, archive_filename)

    # Set directory where release files will be found
    search_dir = tmp_dir_result

    # Download release
    if not DownloadUrl(url=archive_url, output_dir=tmp_dir_result, output_file=archive_file):
        print("Unable to download release from '%s'" % archive_url)
        return False

    # Create install dir if necessary
    system.MakeDirectory(
        dir = install_dir,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Handle app images
    if archive_extension.lower() == ".appimage":

        # Get new appimage file
        appimage_file = os.path.join(tmp_dir_result, install_name + ".AppImage")

        # Rename app image
        system.MoveFileOrDirectory(
            src = archive_file,
            dest = appimage_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Mark app images as executable
        system.MarkAsExecutable(
            src = appimage_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set install files
        install_files = [system.GetFilenameFile(appimage_file)]

    # Executable installer
    elif archive_extension == ".exe" and is_installer and not is_archive:

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
        command.RunBlockingCommand(
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

        # Set search directory to best location for installed files
        search_dir = prefix_dir
        if installer_type != config.installer_format_unknown:
            search_dir = real_install_path
        if not search_dir:
            return False

    # Plain executable (should be just downloaded as a standalone file)
    elif archive_extension == ".exe" and not is_installer and not is_archive:
        pass

    # Otherwise handle regular archives
    else:

        # Extract archive
        archive.ExtractArchive(
            archive_file = archive_file,
            extract_dir = tmp_dir_result,
            verbose = verbose)

    # Further refine search dir if we are looking for a particular file
    if len(search_file):
        for file in system.BuildFileList(search_dir):
            current_dir = system.GetFilenameDirectory(file)
            current_basefile = system.GetFilenameFile(file)
            if current_basefile.endswith(search_file):
                search_dir = current_dir
                break

    # Copy release files
    if len(install_files):
        for install_file in install_files:
            install_file_src = os.path.abspath(os.path.join(search_dir, install_file))
            install_file_dest = os.path.join(install_dir, install_file)
            if os.path.exists(install_file_src):
                system.CopyFileOrDirectory(
                    src = install_file_src,
                    dest = install_file_dest,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
    else:
        system.CopyContents(
            src = search_dir,
            dest = install_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Registry files
    if len(registry_files):
        for registry_file in registry_files:
            registry.ImportRegistryFile(
                registry_file = registry_file,
                prefix_dir = prefix_dir,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Chmod files
    if len(chmod_files):
        for filename in system.BuildFileList(install_dir):
            for chmod_entry in chmod_files:
                chmod_file = system.NormalizeFilePath(chmod_entry["file"])
                chmod_perms = chmod_entry["perms"]
                if filename.endswith(chmod_file):
                    system.ChmodFile(
                        src = filename,
                        perms = chmod_perms,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

    # Rename files
    if len(rename_files):
        for filename in system.BuildFileList(install_dir):
            for rename_entry in rename_files:
                rename_from = rename_entry["from"]
                rename_to = rename_entry["to"]
                if filename.endswith(rename_from):
                    system.MoveFileOrDirectory(
                        src = filename,
                        dest = filename.replace(rename_from, rename_to),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)
    return True

# Download latest github sources
def DownloadLatestGithubSource(
    github_user,
    github_repo,
    output_dir = "",
    clean_first = False,
    verbose = False,
    exit_on_failure = False):

    # Get github url
    github_url = "https://github.com/%s/%s.git" % (github_user, github_repo)

    # Download sources
    success = DownloadGitUrl(
        url = github_url,
        output_dir = output_dir,
        clean_first = clean_first,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Remove git folder
    system.RemoveDirectory(
        dir = os.path.join(output_dir, ".git"),
        verbose = verbose)

    # Check result
    return os.path.isdir(output_dir)

# Download latest github release
def DownloadLatestGithubRelease(
    github_user,
    github_repo,
    starts_with,
    ends_with,
    search_file,
    install_name,
    install_dir,
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    chmod_files = [],
    installer_type = None,
    is_installer = False,
    is_archive = False,
    get_latest = False,
    verbose = False,
    exit_on_failure = False):

    # Get github url
    github_url = "https://api.github.com/repos/%s/%s/releases" % (github_user, github_repo)
    if get_latest:
        github_url = "https://api.github.com/repos/%s/%s/releases/latest" % (github_user, github_repo)

    # Get release json list
    release_json_list = GetRemoteJson(github_url)
    if not release_json_list:
        print("Unable to find github release information from '%s'" % github_url)
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
        print("Unable to find any release from '%s' matching start='%s' and end='%s'" % (github_url, starts_with, ends_with))
        return False

    # Download release
    DownloadGeneralRelease(
        archive_url = archive_url,
        search_file = search_file,
        install_name = install_name,
        install_dir = install_dir,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        install_files = install_files,
        chmod_files = chmod_files,
        installer_type = installer_type,
        is_installer = is_installer,
        is_archive = is_archive,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Download latest webpage release
def DownloadLatestWebpageRelease(
    webpage_url,
    starts_with,
    ends_with,
    search_file,
    install_name,
    install_dir,
    prefix_dir = None,
    prefix_name = None,
    install_files = [],
    chmod_files = [],
    installer_type = None,
    is_installer = False,
    is_archive = False,
    verbose = False,
    exit_on_failure = False):

    # Get archive url
    archive_url = webpage.GetMatchingUrl(
        url = webpage_url,
        starts_with = starts_with,
        ends_with = ends_with,
        get_latest = True,
        verbose = verbose)
    if not archive_url:
        print("Unable to find any release from '%s' matching start='%s' and end='%s'" % (webpage_url, starts_with, ends_with))
        return False

    # Download release
    DownloadGeneralRelease(
        archive_url = archive_url,
        search_file = search_file,
        install_name = install_name,
        install_dir = install_dir,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        install_files = install_files,
        chmod_files = chmod_files,
        installer_type = installer_type,
        is_installer = is_installer,
        is_archive = is_archive,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Build appimage from source
def BuildAppImageFromSource(
    release_url = "",
    webpage_url = "",
    starts_with = "",
    ends_with = "",
    output_name = "",
    output_dir = "",
    build_cmd = "",
    build_dir = "",
    internal_copies = [],
    internal_symlinks = [],
    external_copies = [],
    dependencies = [],
    verbose = False,
    exit_on_failure = False):

    # Only works on linux systems
    if not environment.IsLinuxPlatform():
        return

    # Check params
    system.AssertIsString(release_url, "release_url")
    system.AssertIsString(webpage_url, "webpage_url")
    system.AssertIsString(output_name, "output_name")
    system.AssertIsString(output_dir, "output_dir")
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
            return

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return

    # Install dependencies
    environment.InstallSystemPackages(dependencies)

    # Get directories
    appimage_dir = os.path.join(tmp_dir_result, "AppImage")
    source_dir = os.path.join(tmp_dir_result, "Source")
    download_dir = os.path.join(tmp_dir_result, "Download")
    source_build_dir = source_dir
    if len(build_dir) > 0:
        source_build_dir = os.path.abspath(os.path.join(source_dir, build_dir))

    # Make folders
    system.MakeDirectory(output_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(source_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(appimage_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(download_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Download sources
    if release_url.endswith(".git"):

        # Download git release
        success = DownloadGitUrl(
            url = release_url,
            output_dir = source_dir,
            clean_first = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            print("Unable to download release from '%s'" % release_url)
            sys.exit(1)
    else:

        # Get archive info
        archive_basename = system.GetFilenameBasename(release_url)
        archive_extension = system.GetFilenameExtension(release_url)
        archive_file = os.path.join(download_dir, archive_basename + archive_extension)

        # Download source archive
        success = DownloadUrl(url = release_url, output_file = archive_file)
        if not success:
            print("Unable to download release from '%s'" % release_url)
            sys.exit(1)

        # Extract source archive
        archive.ExtractArchive(
            archive_file = archive_file,
            extract_dir = source_dir,
            verbose = verbose)

    # Make build folder
    system.MakeDirectory(source_build_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Build repository
    command.RunCheckedCommand(
        cmd = build_cmd,
        options = command.CommandOptions(
            cwd = source_build_dir,
            shell = True),
        verbose = verbose)

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
    command.RunCheckedCommand(
        cmd = [programs.GetToolProgram("AppImageTool"), appimage_dir],
        options = command.CommandOptions(
            cwd = tmp_dir_result),
        verbose = verbose)

    # Copy appimage
    for obj in system.GetDirectoryContents(tmp_dir_result):
        if obj.endswith(".AppImage"):
            system.CopyFileOrDirectory(
                src = os.path.join(tmp_dir_result, obj),
                dest = os.path.join(output_dir, output_name + ".AppImage"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            break

    # Copy other objects
    for obj in external_copies:
        src_obj = os.path.join(tmp_dir_result, obj["from"])
        dest_obj = os.path.join(output_dir, obj["to"])
        system.MakeDirectory(os.path.dirname(dest_obj), verbose = verbose, exit_on_failure = exit_on_failure)
        system.CopyFileOrDirectory(
            src = src_obj,
            dest = dest_obj,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)
