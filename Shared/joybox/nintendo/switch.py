# Nintendo Switch files: profiles, trimming XCIs, extracting and installing
# NSPs.

# Imports
import os
import textwrap

# Local imports
from joybox import command
from joybox import fileops
from joybox import hashing
from joybox import paths
from joybox import programs

# Check if switch profile info is valid
def is_valid_switch_profile_info(user_id, account_name):

    # Check user id
    if not isinstance(user_id, str) or len(user_id) != 32:
        return False

    # The id is converted with fromhex, which raises on anything else
    try:
        bytearray.fromhex(user_id)
    except ValueError:
        return False

    # Check account name
    if not isinstance(account_name, str) or len(account_name) > 32:
        return False
    if len(account_name) == 0:
        return False

    # Should be good
    return True

# Create Switch profiles dat
def create_switch_profiles_dat(
    profiles_file,
    user_id,
    account_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check profile info
    if not is_valid_switch_profile_info(user_id, account_name):
        return False

    # Get user id bytes
    user_id_bytes = bytearray.fromhex("".join(reversed(textwrap.wrap(user_id, 2))))

    # Get account name bytes
    account_name_bytes = bytearray(account_name, encoding = "utf-8")

    # Initialize file contents
    file_contents = [b'\x00'] * 1616

    # Write user_id_1
    file_index = 0x10
    for offset in range(0, len(user_id_bytes)):
        file_contents[file_index + offset] = bytes([user_id_bytes[offset]])

    # Write user_id_2
    file_index = 0x20
    for offset in range(0, len(user_id_bytes)):
        file_contents[file_index + offset] = bytes([user_id_bytes[offset]])

    # Write account_name
    file_index = 0x38
    for offset in range(0, len(account_name_bytes)):
        file_contents[file_index + offset] = bytes([account_name_bytes[offset]])

    # Write file
    success = fileops.touch_file(
        src = profiles_file,
        contents = b"".join(file_contents),
        contents_mode = "wb",
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result; a pretend run writes nothing to check
    return pretend_run or os.path.exists(profiles_file)

# Trim Switch XCI file
def trim_switch_xci(
    src_xci_file,
    dest_xci_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    python_tool = programs.find_tool_program("PythonVenvPython")
    if not python_tool:
        return False

    # Get script
    trim_script = programs.find_tool_program("XCITrimmer")
    if not trim_script:
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose, pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_xci_basename = paths.get_filename_basename(src_xci_file)
    tmp_xci_src_file = paths.join_paths(tmp_dir_result, tmp_xci_basename + ".xci")
    tmp_xci_dest_file = paths.join_paths(tmp_dir_result, tmp_xci_basename + "_trimmed.xci")

    # Copy source file
    fileops.copy_file_or_directory(
        src = src_xci_file,
        dest = tmp_xci_src_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    trim_cmd = [
        python_tool,
        trim_script,
        "--trim",
        "--copy",
        tmp_xci_src_file
    ]

    # Run trim command
    code = command.run_returncode_command(
        cmd = trim_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    fileops.move_file_or_directory(
        src = tmp_xci_dest_file,
        dest = dest_xci_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = src_xci_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_xci_file)

# Untrim Switch XCI file
def untrim_switch_xci(
    src_xci_file,
    dest_xci_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    python_tool = programs.find_tool_program("PythonVenvPython")
    if not python_tool:
        return False

    # Get script
    untrim_script = programs.find_tool_program("XCITrimmer")
    if not untrim_script:
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose, pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_xci_basename = paths.get_filename_basename(src_xci_file)
    tmp_xci_src_file = paths.join_paths(tmp_dir_result, tmp_xci_basename + ".xci")
    tmp_xci_dest_file = paths.join_paths(tmp_dir_result, tmp_xci_basename + "_padded.xci")

    # Copy source file
    fileops.copy_file_or_directory(
        src = src_xci_file,
        dest = tmp_xci_src_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    untrim_cmd = [
        python_tool,
        untrim_script,
        "--pad",
        "--copy",
        tmp_xci_src_file
    ]

    # Run untrim command
    code = command.run_returncode_command(
        cmd = untrim_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    fileops.move_file_or_directory(
        src = tmp_xci_dest_file,
        dest = dest_xci_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = src_xci_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_xci_file)

# Extract Switch NSP file
def extract_switch_nsp(
    nsp_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = programs.find_tool_program("HacTool")
    if not extract_tool:
        return False

    # Get extract command
    extract_cmd = [
        extract_tool,
        "-r",
        "-t", "pfs0",
        "--outdir", extract_dir,
        nsp_file
    ]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(extract_dir) and not paths.is_directory_empty(extract_dir)

# Install Switch NSP file
def install_switch_nsp(
    nsp_file,
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

    # Extract nsp file
    success = extract_switch_nsp(
        nsp_file = nsp_file,
        extract_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Look at all the extracted nca files
    for nca_file in paths.build_file_list_by_extensions(tmp_dir_result, extensions = [".nca"]):

        # Get NCA id
        nca_id = paths.get_filename_basename(nca_file)
        if nca_id.endswith(".cnmt"):
            nca_id = paths.get_filename_basename(nca_id)

        # Get NCA dir
        nca_id_bytes = bytes.fromhex(nca_id)
        nca_id_sha256 = hashing.calculate_string_sha256(nca_id_bytes).upper()
        nca_id_dir = "000000%s" % nca_id_sha256[0:2]
        nca_output_dir = paths.join_paths(nand_dir, "user", "Contents", "registered", nca_id_dir)

        # Make NCA dir
        success = fileops.make_directory(
            src = nca_output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Copy NCA file
        success = fileops.copy_file_or_directory(
            src = nca_file,
            dest = paths.join_paths(nca_output_dir, nca_id + ".nca"),
            skip_identical = True,
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
