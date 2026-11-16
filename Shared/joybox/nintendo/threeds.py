# Nintendo 3DS files: converting between CIA and CCI, trimming, extracting
# and installing CIAs into an emulated NAND.

# Imports
import os

# Local imports
from joybox import command
from joybox import fileops
from joybox import filebulk
from joybox import paths
from joybox import programs

# Convert 3DS CIA file to CCI file
def convert_3ds_cia_to_cci(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    convert_tool = programs.find_tool_program("CtrMakeRom")
    if not convert_tool:
        return False

    # Get convert command
    convert_cmd = [
        convert_tool,
        "-ciatocci",
        src_3ds_file,
        "-o", dest_3ds_file
    ]

    # Run convert command
    code = command.run_returncode_command(
        cmd = convert_cmd,
        options = command.create_command_options(
            blocking_processes = [convert_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(dest_3ds_file)

# Convert 3DS CCI file to CIA file
def convert_3ds_cci_to_cia(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    convert_tool = programs.find_tool_program("CtrMakeRom")
    if not convert_tool:
        return False

    # Get convert command
    convert_cmd = [
        convert_tool,
        "-ccitocia",
        src_3ds_file,
        "-o", dest_3ds_file
    ]

    # Run convert command
    code = command.run_returncode_command(
        cmd = convert_cmd,
        options = command.create_command_options(
            blocking_processes = [convert_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(dest_3ds_file)

# Trim 3DS CCI file
def trim_3ds_cci(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    trim_tool = programs.find_tool_program("3DSRomTool")
    if not trim_tool:
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose, pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_3ds_file = paths.join_paths(tmp_dir_result, "temp.3ds")

    # Copy source file
    fileops.copy_file_or_directory(
        src = src_3ds_file,
        dest = tmp_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    trim_cmd = [
        trim_tool,
        "--trim",
        tmp_3ds_file
    ]

    # Run trim command
    code = command.run_returncode_command(
        cmd = trim_cmd,
        options = command.create_command_options(
            blocking_processes = [trim_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    fileops.move_file_or_directory(
        src = tmp_3ds_file,
        dest = dest_3ds_file,
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
    return os.path.exists(dest_3ds_file)

# Untrim 3DS CCI file
def untrim_3ds_cci(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    trim_tool = programs.find_tool_program("3DSRomTool")
    if not trim_tool:
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_3ds_file = paths.join_paths(tmp_dir_result, "temp.3ds")

    # Copy source file
    fileops.copy_file_or_directory(
        src = src_3ds_file,
        dest = tmp_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    trim_cmd = [
        trim_tool,
        "--restore",
        tmp_3ds_file
    ]

    # Run trim command
    code = command.run_returncode_command(
        cmd = trim_cmd,
        options = command.create_command_options(
            blocking_processes = [trim_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    fileops.move_file_or_directory(
        src = tmp_3ds_file,
        dest = dest_3ds_file,
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
    return os.path.exists(dest_3ds_file)

# Extract 3DS CIA file
def extract_3ds_cia(
    src_3ds_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = programs.find_tool_program("CtrTool")
    if not extract_tool:
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Get temporary files
    tmp_file_cer = paths.join_paths(tmp_dir_result, "00000000.cer")
    tmp_file_tik = paths.join_paths(tmp_dir_result, "00000000.tik")
    tmp_file_tmd = paths.join_paths(tmp_dir_result, "00000000.tmd")
    tmp_base_contents = paths.join_paths(tmp_dir_result, "contents")

    # Get extract command
    extract_cmd = [
        extract_tool,
        "--contents", tmp_base_contents,
        "--certs", tmp_file_cer,
        "--tik", tmp_file_tik,
        "--tmd", tmp_file_tmd,
        src_3ds_file
    ]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Rename app files
    for obj in paths.get_directory_contents(tmp_dir_result):
        if obj.startswith("contents"):
            obj_path = paths.join_paths(tmp_dir_result, obj)
            obj_basename = paths.get_filename_extension(obj).strip(".")
            fileops.move_file_or_directory(
                src = obj_path,
                dest = paths.join_paths(tmp_dir_result, obj_basename + ".app"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Move extracted files
    filebulk.move_contents(
        src = tmp_dir_result,
        dest = extract_dir,
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
    return os.path.exists(extract_dir) and not paths.is_directory_empty(extract_dir)

# Get 3DS file info
def get_3ds_file_info(
    src_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    print_tool = programs.find_tool_program("CtrTool")
    if not print_tool:
        return ""

    # Get print command
    print_cmd = [
        print_tool,
        src_3ds_file
    ]

    # Run print command
    output = command.run_output_command(
        cmd = print_cmd,
        options = command.create_command_options(
            blocking_processes = [print_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return output

# Install 3DS CIA file
def install_3ds_cia(
    src_3ds_file,
    sdmc_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get file info
    file_info = get_3ds_file_info(
        src_3ds_file = src_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(file_info) == 0:
        return False

    # Get title id
    app_titleid = ""
    for line in file_info.split("\n"):
        if line.startswith("Title id:"):
            line_tokens = line.split(":")
            if len(line_tokens) == 2:
                app_titleid = line_tokens[1].strip()
                break
    if len(app_titleid) != 16:
        return False

    # Get app info
    app_type = app_titleid[:8].lower()
    app_folder = app_titleid[8:].lower()
    app_base_dir = paths.join_paths(sdmc_dir, "Nintendo 3DS", "00000000000000000000000000000000", "00000000000000000000000000000000", "title")
    app_install_dir = paths.join_paths(app_base_dir, app_type, app_folder, "content")

    # Extract cia file
    success = extract_3ds_cia(
        src_3ds_file = src_3ds_file,
        extract_dir = app_install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Should be installed
    return True

######################################################
