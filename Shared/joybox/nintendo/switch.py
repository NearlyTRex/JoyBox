# Nintendo Switch files: profiles, trimming XCIs, extracting and installing
# NSPs.

# Imports
import os
import textwrap

# Local imports
from joybox import command
from joybox import commandbase
from joybox import fileops
from joybox import hashutil
from joybox import paths
from joybox import programs
from joybox.nintendo import switchprofile

# Create Switch profiles dat
def create_switch_profiles_dat(
    profiles_file,
    user_id,
    account_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check profile info
    if not switchprofile.is_valid_switch_profile_info(user_id, account_name):
        return False

    # Get user id bytes
    user_id_bytes = bytearray.fromhex("".join(reversed(textwrap.wrap(user_id, 2))))

    # Get account name bytes
    account_name_bytes = bytearray(account_name, encoding = "utf-8")

    # Initialize file contents
    file_contents = [b'\x00'] * 1616

    # Write user_id_1
    file_index = 0x10
    for offset, value in enumerate(user_id_bytes):
        file_contents[file_index + offset] = bytes([value])

    # Write user_id_2
    file_index = 0x20
    for offset, value in enumerate(user_id_bytes):
        file_contents[file_index + offset] = bytes([value])

    # Write account_name
    file_index = 0x38
    for offset, value in enumerate(account_name_bytes):
        file_contents[file_index + offset] = bytes([value])

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

# Run XCITrimmer in mode "--trim" or "--pad" over a copy of an xci in a temporary directory,
# moving the file it writes, named with the suffix given, to the destination
def run_xci_trimmer(mode, output_suffix, src_xci_file, dest_xci_file, delete_original = False, verbose = False, pretend_run = False, exit_on_failure = False):
    script_cmd = programs.get_python_script_command("XCITrimmer")
    if not script_cmd:
        return False
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        tmp_xci_basename = paths.get_filename_basename(src_xci_file)
        tmp_xci_src_file = paths.join_paths(tmp_dir, tmp_xci_basename + ".xci")
        fileops.copy_file_or_directory(
            src = src_xci_file,
            dest = tmp_xci_src_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        code = command.run_returncode_command(
            cmd = script_cmd + [mode, "--copy", tmp_xci_src_file],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False
        fileops.move_file_or_directory(
            src = paths.join_paths(tmp_dir, tmp_xci_basename + output_suffix),
            dest = dest_xci_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if delete_original:
        fileops.remove_file(
            src = src_xci_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return os.path.exists(dest_xci_file)

# Trim Switch XCI file
def trim_switch_xci(
    src_xci_file,
    dest_xci_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_xci_trimmer(
        "--trim", "_trimmed.xci", src_xci_file, dest_xci_file, delete_original, verbose, pretend_run, exit_on_failure)

# Untrim Switch XCI file
def untrim_switch_xci(
    src_xci_file,
    dest_xci_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_xci_trimmer(
        "--pad", "_padded.xci", src_xci_file, dest_xci_file, delete_original, verbose, pretend_run, exit_on_failure)

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
        options = commandbase.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(extract_dir) and not paths.is_directory_empty(extract_dir)

# Install an extracted NCA file into a nand, under the registered directory its id hashes to
def install_switch_nca(nca_file, nand_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    nca_id = paths.get_filename_basename(nca_file)
    if nca_id.endswith(".cnmt"):
        nca_id = paths.get_filename_basename(nca_id)
    nca_id_sha256 = hashutil.calculate_string_sha256(bytes.fromhex(nca_id)).upper()
    nca_output_dir = paths.join_paths(nand_dir, "user", "Contents", "registered", "000000%s" % nca_id_sha256[0:2])
    success = fileops.make_directory(
        src = nca_output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return fileops.copy_file_or_directory(
        src = nca_file,
        dest = paths.join_paths(nca_output_dir, nca_id + ".nca"),
        skip_identical = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Install Switch NSP file
def install_switch_nsp(
    nsp_file,
    nand_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Extract the nsp in a temporary directory and install each nca it holds
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        success = extract_switch_nsp(
            nsp_file = nsp_file,
            extract_dir = tmp_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        for nca_file in paths.build_file_list_by_extensions(tmp_dir, extensions = [".nca"]):
            if not install_switch_nca(nca_file, nand_dir, verbose, pretend_run, exit_on_failure):
                return False
    return True
