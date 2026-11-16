# Nintendo Wii U NUS packages: decrypting, verifying and installing them, and
# keeping the keys file up to date.

# Imports
import os

# Local imports
from joybox import command
from joybox import config
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import serialization
from joybox import webpage

# Decrypt Wii U NUS package
def decrypt_wiiu_nus_package(
    nus_package_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    decrypt_tool = None
    if programs.is_tool_installed("CDecrypt"):
        decrypt_tool = programs.get_tool_program("CDecrypt")
    if not decrypt_tool:
        logger.log_error("CDecrypt was not found")
        return False

    # Get input files
    input_file_tmd = paths.join_paths(nus_package_dir, "title.tmd")
    input_file_tik = paths.join_paths(nus_package_dir, "title.tik")
    if not os.path.exists(input_file_tmd) or not os.path.exists(input_file_tik):
        return False

    # Get decrypt command
    decrypt_cmd = [
        decrypt_tool,
        input_file_tmd,
        input_file_tik
    ]

    # Run decrypt command
    code = command.run_returncode_command(
        cmd = decrypt_cmd,
        options = command.create_command_options(
            cwd = nus_package_dir,
            output_paths = [nus_package_dir],
            blocking_processes = [decrypt_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        for obj in paths.get_directory_contents(nus_package_dir):
            obj_path = paths.join_paths(nus_package_dir, obj)
            if not paths.is_path_file(obj_path):
                continue
            obj_ext = paths.get_filename_extension(obj_path)
            if obj_ext in config.NintendoWiiUFileType.cvalues():
                fileops.remove_file(
                    src = obj_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

    # Should be decrypted now
    return True

# Verify Wii U NUS package
def verify_wiiu_nus_package(
    nus_package_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Copy package
    filebulk.copy_contents(
        src = nus_package_dir,
        dest = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Test decryption
    decryption_result = decrypt_wiiu_nus_package(
        nus_package_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return decryption_result

# Install Wii U NUS package
def install_wiiu_nus_package(
    nus_package_dir,
    nand_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Copy package
    filebulk.copy_contents(
        src = nus_package_dir,
        dest = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if paths.is_directory_empty(tmp_dir_result):
        return False

    # Decrypt package
    success = decrypt_wiiu_nus_package(
        nus_package_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get app xml
    app_xml_file = paths.join_paths(tmp_dir_result, "code", "app.xml")
    if not os.path.exists(app_xml_file):
        return False

    # Get title id
    app_titleid = ""
    app_xml_contents = serialization.read_text_file(
        src = app_xml_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    soup = webpage.parse_xml_page_source(app_xml_contents) if app_xml_contents else None
    if soup:
        for tag in soup.find_all("title_id"):
            app_titleid = tag.text
    if len(app_titleid) != 16:
        return False

    # Get app info
    app_type = app_titleid[:8].lower()
    app_folder = app_titleid[8:].lower()

    # Look at each extracted folder
    for obj in ["code", "content", "meta"]:

        # Make folder
        success = fileops.make_directory(
            src = paths.join_paths(tmp_dir_result, obj),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Move folder
        success = fileops.move_file_or_directory(
            src = paths.join_paths(tmp_dir_result, obj),
            dest = paths.join_paths(nand_dir, "usr", "title", app_type, app_folder, obj),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be installed
    return True

# Update Wii U keys file
def update_wiiu_keys(
    src_key_file,
    dest_key_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Read keys
    key_sets = []
    for key_file in [dest_key_file, src_key_file]:
        key_contents = serialization.read_text_file(
            src = key_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if key_contents is None:
            logger.log_error("Unable to read Wii U keys file %s" % key_file)
            return False
        key_sets.append({line.strip() for line in key_contents.splitlines() if line.strip()})

    # Write keys
    return serialization.write_text_file(
        src = dest_key_file,
        contents = "".join("%s\n" % key for key in sorted(set.union(*key_sets))),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

######################################################
