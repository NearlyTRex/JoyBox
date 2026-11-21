# Imports
import os
import os.path

# Local imports
import joybox.config as config
import joybox.fileops as fileops
import joybox.paths as paths
import joybox.archive as archive

# Check if install image is mounted
def is_install_image_mounted(install_file, mount_dir):
    return paths.does_directory_contain_files(mount_dir)

# Mount install image
def mount_install_image(
    install_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if paths.is_directory_empty(mount_dir):
        return unpack_install_image(
            input_image = install_file,
            output_dir = mount_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

# Copy an install's files into a directory, leaving out the paths installs ignore
def copy_install_files(input_dir, output_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for relative_path in paths.build_file_list(input_dir, use_relative_paths = True):
        if relative_path.startswith(tuple(config.ignored_paths_install)):
            continue
        path_to = paths.join_paths(output_dir, relative_path)
        fileops.make_directory(
            src = paths.get_filename_directory(path_to),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        fileops.copy_file_or_directory(
            src = paths.join_paths(input_dir, relative_path),
            dest = path_to,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Pack install image
def pack_install_image(
    input_dir,
    output_image,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Archive a copy of the install's files from a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        copy_install_files(input_dir, tmp_dir, verbose, pretend_run, exit_on_failure)
        if not paths.does_directory_contain_files(tmp_dir):
            return False
        success = archive.create_archive_from_folder(
            archive_file = output_image,
            source_dir = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    if delete_original:
        fileops.remove_directory(
            src = input_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return os.path.exists(output_image)

# Unpack install image
def unpack_install_image(
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
