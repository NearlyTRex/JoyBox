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
    decrypt_tool = programs.find_tool_program("CDecrypt")
    if not decrypt_tool:
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

    # Test decrypting a copy of the package in a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        filebulk.copy_contents(
            src = nus_package_dir,
            dest = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return decrypt_wiiu_nus_package(
            nus_package_dir = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Get the title id a decrypted package's app xml names, or "" when it has none of 16 characters
def get_wiiu_package_title_id(package_dir, verbose = False, exit_on_failure = False):
    app_xml_file = paths.join_paths(package_dir, "code", "app.xml")
    if not os.path.exists(app_xml_file):
        return ""
    app_titleid = ""
    app_xml_contents = serialization.read_text_file(
        src = app_xml_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    soup = webpage.parse_xml_page_source(app_xml_contents) if app_xml_contents else None
    if soup:
        for tag in soup.find_all("title_id"):
            app_titleid = tag.text
    return app_titleid if len(app_titleid) == 16 else ""

# Move a decrypted package's folders into a nand, under the title its id names
def move_wiiu_title_folders(package_dir, nand_dir, app_titleid, verbose = False, pretend_run = False, exit_on_failure = False):
    title_dir = paths.join_paths(nand_dir, "usr", "title", app_titleid[:8].lower(), app_titleid[8:].lower())
    for obj in ["code", "content", "meta"]:
        success = fileops.make_directory(
            src = paths.join_paths(package_dir, obj),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = fileops.move_file_or_directory(
            src = paths.join_paths(package_dir, obj),
            dest = paths.join_paths(title_dir, obj),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Install Wii U NUS package
def install_wiiu_nus_package(
    nus_package_dir,
    nand_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Decrypt a copy of the package in a temporary directory, then move it into the nand
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        filebulk.copy_contents(
            src = nus_package_dir,
            dest = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if paths.is_directory_empty(tmp_dir):
            return False
        success = decrypt_wiiu_nus_package(
            nus_package_dir = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        app_titleid = get_wiiu_package_title_id(tmp_dir, verbose, exit_on_failure)
        if not app_titleid:
            return False
        return move_wiiu_title_folders(tmp_dir, nand_dir, app_titleid, verbose, pretend_run, exit_on_failure)

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
