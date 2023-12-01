# Imports
import os, os.path
import sys
import json

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import environment
import system
import archive

# Check if install image is mounted
def IsInstallImageMounted(install_file, mount_dir):
    return system.DoesDirectoryContainFiles(mount_dir)

# Mount install image
def MountInstallImage(install_file, mount_dir, verbose = False, exit_on_failure = False):
    if system.IsDirectoryEmpty(mount_dir):
        return UnpackInstallImage(
            input_image = install_file,
            output_dir = mount_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    return True

# Pack install image
def PackInstallImage(input_dir, output_image, delete_original = False, verbose = False, exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Copy important paths
    for relative_path in system.BuildFileList(input_dir, use_relative_paths = True):

        # Skip ignored paths
        should_ignore = False
        for ignore_path in config.ignored_paths_install:
            if relative_path.startswith(ignore_path):
                should_ignore = True
                break
        if should_ignore:
            continue

        # Copy path
        path_from = os.path.join(input_dir, relative_path)
        path_to = os.path.join(tmp_dir_result, relative_path)
        system.MakeDirectory(
            dir = system.GetFilenameDirectory(path_to),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.CopyFileOrDirectory(
            src = path_from,
            dest = path_to,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # There are no files to pack
    if not system.DoesDirectoryContainFiles(tmp_dir_result):
        return False

    # Create archive
    success = archive.CreateZipFromFolder(
        zip_file = output_image,
        source_dir = tmp_dir_result,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean up
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)
    if delete_original:
        system.RemoveDirectory(input_dir, verbose = verbose)

    # Check result
    return os.path.exists(output_image)

# Unpack install image
def UnpackInstallImage(input_image, output_dir, delete_original = False, verbose = False, exit_on_failure = False):
    return archive.ExtractArchive(
        archive_file = input_image,
        extract_dir = output_dir,
        delete_original = delete_original,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
