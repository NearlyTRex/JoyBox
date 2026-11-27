# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import logger
from joybox import fileops
from joybox import filebulk
from joybox import archive
from joybox import archiveinfo
from joybox import strings
from joybox import webfetch
from joybox import network
from joybox import paths
from joybox import locker

# Backups that failed this run. A copy in a locker is there to reinstall from
# offline, so its failure is reported but never undoes an install that worked.
failed_backups = []

# Record a backup that failed
def note_failed_backup(backup_dest):
    failed_backups.append(backup_dest)
    logger.log_warning("Unable to back up %s to the lockers; the install itself is fine" % backup_dest)

# Remove a temporary directory, tolerating failure
def remove_temporary_directory(tmp_dir, verbose = False, pretend_run = False):
    fileops.remove_directory(
        src = tmp_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)

# Archive picked from those found in archive_dir: the first whose name contains preferred_archive, else the first or last
# None with an error when there are none or the pick does not exist
def select_stored_archive(archive_dir, potential_archives, preferred_archive, use_first_found, use_last_found):
    if len(potential_archives) == 0:
        logger.log_error("No available archives found in '%s'" % archive_dir)
        return None
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
        return None
    return selected_archive

# Install a release archive already in archive_dir, picked by name or as the first or last found; True when skipping a missing locker copy
def setup_stored_release(
    archive_dir,
    install_name,
    install_dir,
    preferred_archive = None,
    use_first_found = False,
    use_last_found = True,
    search_file = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    skip_if_missing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get list of potential archives
    potential_archives = paths.build_file_list(archive_dir)

    # Optionally skip when no usable archive is present (e.g. locker not downloaded).
    # This treats a missing directory, an empty directory, or a directory holding
    # only non-archive files all as "nothing to install" so setup can continue.
    if skip_if_missing and not any(archiveinfo.is_archive(potential_archive) for potential_archive in potential_archives):
        logger.log_warning("Skipping %s: no stored archives available in '%s' (locker not downloaded?)" % (install_name, archive_dir))
        return True

    # Select archive file
    selected_archive = select_stored_archive(archive_dir, potential_archives, preferred_archive, use_first_found, use_last_found)
    if selected_archive is None:
        return False

    # Setup selected archive
    return setup_general_release(
        archive_file = selected_archive, install_name = install_name, install_dir = install_dir,
        search_file = search_file, install_files = install_files, chmod_files = chmod_files,
        rename_files = rename_files, release_type = release_type,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Release type an archive's name implies: archive for zip, 7z, rar and tarballs, program for exe and AppImage; None otherwise
def guess_release_type(archive_file):
    archive_is_zip = archiveinfo.is_zip_archive(archive_file)
    archive_is_7z = archiveinfo.is_7z_archive(archive_file)
    archive_is_rar = archiveinfo.is_rar_archive(archive_file)
    archive_is_tarball = archiveinfo.is_tarball_archive(archive_file)
    archive_is_exe = archiveinfo.is_exe_archive(archive_file)
    archive_is_appimage = archiveinfo.is_appimage_archive(archive_file)
    if archive_is_zip or archive_is_7z or archive_is_rar or archive_is_tarball:
        return config.ReleaseType.ARCHIVE
    if archive_is_exe or archive_is_appimage:
        return config.ReleaseType.PROGRAM
    return None

# Copy an AppImage into tmp_dir_result under the install name and mark it executable; its file name, or None on failure
def stage_appimage_release(
    archive_file,
    install_name,
    tmp_dir_result,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get new appimage file
    appimage_file = paths.join_paths(tmp_dir_result, install_name + ".AppImage")

    # Copy app image
    success = filebulk.smart_copy(
        src = archive_file,
        dest = appimage_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to copy app image")
        return None

    # Mark app images as executable
    success = fileops.mark_as_executable(
        src = appimage_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to mark app image as executable")
        return None
    return paths.get_filename_file(appimage_file)

# Stage a release by its type, guessed from the archive name when not given: an AppImage copied in, another program used where it is, or an archive extracted into tmp_dir_result
# Returns the dir to search for its files and the install files to use instead of the given ones (None to keep them); None on failure
def stage_release(
    archive_file,
    install_name,
    tmp_dir_result,
    release_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Guess the release type if none specified
    if not release_type:
        release_type = guess_release_type(archive_file)

    # Standalone program
    if release_type == config.ReleaseType.PROGRAM:
        if paths.get_filename_extension(archive_file).lower() != ".appimage":
            return paths.get_filename_directory(archive_file), None
        appimage_name = stage_appimage_release(
            archive_file, install_name, tmp_dir_result,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        if appimage_name is None:
            return None
        return tmp_dir_result, [appimage_name]

    # Archive
    if release_type == config.ReleaseType.ARCHIVE:
        success = archive.extract_archive(
            archive_file = archive_file,
            extract_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to extract downloaded release archive %s" % archive_file)
            return None
        return tmp_dir_result, None

    # Unknown
    logger.log_error("Unknown release type, please specify it")
    return None

# Directory of the first file under search_dir ending with search_file; search_dir itself when there is none or no search_file
def find_release_search_dir(search_dir, search_file):
    if isinstance(search_file, str) and len(search_file):
        for file in paths.build_file_list(search_dir):
            if file.endswith(search_file):
                return paths.get_filename_directory(file)
    return search_dir

# Copy the listed install files from search_dir into install_dir, or all its contents when none are listed; False on failure
def copy_release_files(
    search_dir,
    install_dir,
    install_files,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not isinstance(install_files, list) or not install_files:
        success = filebulk.copy_contents(
            src = search_dir,
            dest = install_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy install files from %s" % search_dir)
        return success
    for install_file in install_files:
        install_file_src = os.path.abspath(paths.join_paths(search_dir, install_file))
        install_file_dest = paths.join_paths(install_dir, install_file)
        success = filebulk.smart_copy(
            src = install_file_src,
            dest = install_file_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy install file %s" % install_file)
            return False
    return True

# Apply the perms of every chmod entry whose file the installed file's path ends with; False on failure
def chmod_release_file(
    filename,
    chmod_files,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for chmod_entry in chmod_files:
        chmod_file = paths.normalize_file_path(chmod_entry["file"])
        chmod_perms = chmod_entry["perms"]
        if not filename.endswith(chmod_file):
            continue
        success = fileops.chmod_file_or_directory(
            src = filename,
            perms = chmod_perms,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to update permissions for %s" % filename)
            return False
    return True

# Rename an installed file by the first rename entry whose name it resembles past the entry's ratio; False on failure
def rename_release_file(
    filename,
    rename_files,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    filename_dir = paths.get_filename_directory(filename)
    filename_file = paths.get_filename_file(filename)
    for rename_entry in rename_files:
        rename_from = rename_entry["from"]
        rename_to = rename_entry["to"]
        rename_ratio = rename_entry["ratio"]
        if strings.get_string_similarity_ratio(rename_from, filename_file) <= rename_ratio:
            continue
        success = filebulk.smart_move(
            src = filename,
            dest = paths.join_paths(filename_dir, rename_to),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to rename file %s" % filename)
            return False
        return True
    return True

# Copy the release files into install_dir, then apply the chmod and rename entries to what landed; False on failure
def install_release_files(
    search_dir,
    install_dir,
    install_files,
    chmod_files,
    rename_files,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get files
    install_files = [] if install_files is None else install_files
    chmod_files = [] if chmod_files is None else chmod_files
    rename_files = [] if rename_files is None else rename_files

    # Copy release files
    if not copy_release_files(search_dir, install_dir, install_files, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
        return False

    # Chmod files
    if isinstance(chmod_files, list) and chmod_files:
        for filename in paths.build_file_list(install_dir):
            if not chmod_release_file(filename, chmod_files, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False

    # Rename files
    if isinstance(rename_files, list) and rename_files:
        for filename in paths.build_file_list(install_dir):
            if not rename_release_file(filename, rename_files, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False
    return True

# Back the release archive up to the lockers under backups_dir, noting rather than failing on an unsuccessful backup
def backup_release_archive(
    archive_file,
    backups_dir,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    backup_dest = paths.join_paths(backups_dir, paths.get_filename_file(archive_file))
    dest_rel_path = locker.convert_to_relative_path(backup_dest)
    success = locker.backup(
        src = archive_file,
        dest_rel_path = dest_rel_path,
        locker_type = locker_type,
        show_progress = True,
        skip_existing = True,
        skip_identical = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        note_failed_backup(backup_dest)

# Create install_dir, stage the release in tmp_dir_result and install its files there with the chmod and rename entries; False on failure
def unpack_release(
    archive_file,
    install_name,
    install_dir,
    tmp_dir_result,
    search_file = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create install dir if necessary
    success = fileops.make_directory(
        src = install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to create install directory %s" % install_dir)
        return False

    # Stage the release, then refine search dir if we are looking for a particular file
    staged = stage_release(
        archive_file, install_name, tmp_dir_result, release_type,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    if not staged:
        return False
    search_dir, staged_install_files = staged
    if staged_install_files is not None:
        install_files = staged_install_files
    search_dir = find_release_search_dir(search_dir, search_file)

    # Copy, chmod and rename release files
    return install_release_files(
        search_dir, install_dir, install_files, chmod_files, rename_files,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Install a release using an existing temporary directory
def install_general_release(
    archive_file,
    install_name,
    install_dir,
    tmp_dir_result,
    search_file = None,
    backups_dir = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Unpack and install release files
    success = unpack_release(
        archive_file, install_name, install_dir, tmp_dir_result,
        search_file = search_file, install_files = install_files, chmod_files = chmod_files,
        rename_files = rename_files, release_type = release_type,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Backup files
    if not skip_autobackup and paths.is_path_valid(backups_dir):
        backup_release_archive(
            archive_file, backups_dir, locker_type,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return paths.does_directory_contain_files(install_dir)

# Install a local release archive into install_dir by way of a temporary directory; True when install_dir ends up with files
def setup_general_release(
    archive_file,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Install release from a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
        if not tmp_dir_result:
            logger.log_error("Unable to create temporary directory")
            return False
        return install_general_release(
            archive_file = archive_file,
            install_name = install_name,
            install_dir = install_dir,
            tmp_dir_result = tmp_dir_result,
            search_file = search_file,
            backups_dir = backups_dir,
            install_files = install_files,
            chmod_files = chmod_files,
            rename_files = rename_files,
            release_type = release_type,
            locker_type = locker_type,
            skip_autobackup = skip_autobackup,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Download the archive at archive_url into tmp_dir_result under its own name; its path, or None with an error on failure
def download_release_archive(archive_url, tmp_dir_result, verbose = False, pretend_run = False, exit_on_failure = False):
    archive_file = paths.join_paths(tmp_dir_result, paths.get_filename_file(archive_url))
    success = network.download_url(
        url = archive_url,
        output_file = archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to download release from '%s'" % archive_url)
        return None
    return archive_file

# Download a release archive by URL into a temporary directory and install it from there
def download_general_release(
    archive_url,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Download release into a temporary directory and set it up from there
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
        if not tmp_dir_result:
            logger.log_error("Unable to create temporary directory")
            return False

        # Download release
        archive_file = download_release_archive(
            archive_url, tmp_dir_result,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        if not archive_file:
            return False

        # Setup release
        return setup_general_release(
            archive_file = archive_file, install_name = install_name, install_dir = install_dir,
            search_file = search_file, backups_dir = backups_dir, install_files = install_files,
            chmod_files = chmod_files, rename_files = rename_files, release_type = release_type,
            locker_type = locker_type, skip_autobackup = skip_autobackup,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Find the first release asset whose name matches the given prefix and suffix
def find_github_asset_url(release_json_list, starts_with, ends_with):
    starts_with = starts_with or ""
    ends_with = ends_with or ""
    if not starts_with and not ends_with:
        return ""
    for release_json in release_json_list:
        if not isinstance(release_json, dict):
            continue
        releases_assets = release_json.get("assets")
        if not isinstance(releases_assets, list):
            continue
        for releases_asset in releases_assets:
            if not isinstance(releases_asset, dict):
                continue
            browser_download_file = releases_asset.get("name")
            browser_download_url = releases_asset.get("browser_download_url")
            if not isinstance(browser_download_file, str) or not isinstance(browser_download_url, str) or not browser_download_url:
                continue
            if browser_download_file.startswith(starts_with) and browser_download_file.endswith(ends_with):
                return browser_download_url
    return ""

# Download URL of the first asset matching the prefix and suffix in the repo's releases, or only its latest; "" with an error when none
def find_github_release_url(
    github_user,
    github_repo,
    starts_with,
    ends_with,
    get_latest = False,
    verbose = False,
    exit_on_failure = False):

    # Get github url
    github_url = "https://api.github.com/repos/%s/%s/releases" % (github_user, github_repo)
    if get_latest:
        github_url = "https://api.github.com/repos/%s/%s/releases/latest" % (github_user, github_repo)

    # Get release json list
    release_json_list = network.get_remote_json(
        url = github_url,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not release_json_list:
        logger.log_error("Unable to find github release information from '%s'" % github_url)
        return ""
    if not isinstance(release_json_list, list):
        release_json_list = [release_json_list]

    # Find matching archive url
    archive_url = find_github_asset_url(release_json_list, starts_with, ends_with)
    if not archive_url:
        logger.log_error("Unable to find any release from '%s' matching start='%s' and end='%s'" % (github_url, starts_with, ends_with))
    return archive_url

# Install the first GitHub release asset whose name has the given prefix and suffix, from all releases or only the latest
def download_github_release(
    github_user,
    github_repo,
    starts_with,
    ends_with,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    get_latest = False,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find matching archive url
    archive_url = find_github_release_url(
        github_user, github_repo, starts_with, ends_with,
        get_latest = get_latest, verbose = verbose, exit_on_failure = exit_on_failure)
    if not archive_url:
        return False

    # Download release
    return download_general_release(
        archive_url = archive_url, install_name = install_name, install_dir = install_dir,
        search_file = search_file, backups_dir = backups_dir, install_files = install_files,
        chmod_files = chmod_files, rename_files = rename_files, release_type = release_type,
        locker_type = locker_type, skip_autobackup = skip_autobackup,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Install the release a web page links to, the link chosen by its prefix and suffix
def download_webpage_release(
    webpage_url,
    webpage_base_url,
    starts_with,
    ends_with,
    install_name,
    install_dir,
    search_file = None,
    backups_dir = None,
    install_files = None,
    chmod_files = None,
    rename_files = None,
    release_type = None,
    get_latest = False,
    locker_type = None,
    skip_autobackup = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get archive url
    archive_url = webfetch.get_matching_url(
        url = webpage_url, base_url = webpage_base_url,
        starts_with = starts_with, ends_with = ends_with, get_latest = get_latest,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    if not archive_url:
        logger.log_error("Unable to find any release from '%s' matching start='%s' and end='%s'" % (webpage_url, starts_with, ends_with))
        return False

    # Download release
    return download_general_release(
        archive_url = archive_url, install_name = install_name, install_dir = install_dir,
        search_file = search_file, backups_dir = backups_dir, install_files = install_files,
        chmod_files = chmod_files, rename_files = rename_files, release_type = release_type,
        locker_type = locker_type, skip_autobackup = skip_autobackup,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
