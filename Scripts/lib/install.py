# Imports
import os, os.path
import sys
import json

# Local imports
import config
import environment
import fileops
import paths
import system
import archive

# Check if install image is mounted
def IsInstallImageMounted(install_file, mount_dir):
    return paths.does_directory_contain_files(mount_dir)

# Mount install image
def MountInstallImage(
    install_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if paths.is_directory_empty(mount_dir):
        return UnpackInstallImage(
            input_image = install_file,
            output_dir = mount_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

# Pack install image
def PackInstallImage(
    input_dir,
    output_image,
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

    # Copy important paths
    for relative_path in paths.build_file_list(input_dir, use_relative_paths = True):

        # Skip ignored paths
        should_ignore = False
        for ignore_path in config.ignored_paths_install:
            if relative_path.startswith(ignore_path):
                should_ignore = True
                break
        if should_ignore:
            continue

        # Copy path
        path_from = paths.join_paths(input_dir, relative_path)
        path_to = paths.join_paths(tmp_dir_result, relative_path)
        fileops.make_directory(
            src = paths.get_filename_directory(path_to),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        fileops.copy_file_or_directory(
            src = path_from,
            dest = path_to,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # There are no files to pack
    if not paths.does_directory_contain_files(tmp_dir_result):
        return False

    # Create archive
    success = archive.create_archive_from_folder(
        archive_file = output_image,
        source_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean up
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if delete_original:
        fileops.remove_directory(
            src = input_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_image)

# Unpack install image
def UnpackInstallImage(
    input_image,
    output_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return archive.extract_archive(
        archive_file = input_image,
        extract_dir = output_dir,
        delete_original = delete_original,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
