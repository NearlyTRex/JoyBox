# Nintendo 3DS files: converting between CIA and CCI, trimming, extracting
# and installing CIAs into an emulated NAND.

# Imports
import os

# Local imports
from joybox import command
from joybox import commandbase
from joybox import fileops
from joybox import filebulk
from joybox import logger
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
        options = commandbase.create_command_options(
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
        options = commandbase.create_command_options(
            blocking_processes = [convert_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(dest_3ds_file)

# Run 3DSRomTool in mode "--trim" or "--restore" over a copy of a cci in a temporary
# directory, which it rewrites in place, then move the copy to the destination
def run_3ds_rom_tool(mode, src_3ds_file, dest_3ds_file, verbose = False, pretend_run = False, exit_on_failure = False):
    trim_tool = programs.find_tool_program("3DSRomTool")
    if not trim_tool:
        return False
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        tmp_3ds_file = paths.join_paths(tmp_dir, "temp.3ds")
        fileops.copy_file_or_directory(
            src = src_3ds_file,
            dest = tmp_3ds_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        code = command.run_returncode_command(
            cmd = [trim_tool, mode, tmp_3ds_file],
            options = commandbase.create_command_options(
                blocking_processes = [trim_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False
        fileops.move_file_or_directory(
            src = tmp_3ds_file,
            dest = dest_3ds_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return os.path.exists(dest_3ds_file)

# Trim 3DS CCI file
def trim_3ds_cci(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_3ds_rom_tool("--trim", src_3ds_file, dest_3ds_file, verbose, pretend_run, exit_on_failure)

# Untrim 3DS CCI file
def untrim_3ds_cci(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_3ds_rom_tool("--restore", src_3ds_file, dest_3ds_file, verbose, pretend_run, exit_on_failure)

# Rename the contents files ctrtool extracted to .app files, named by their extension
def rename_3ds_cia_contents(extract_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for obj in paths.get_directory_contents(extract_dir):
        if obj.startswith("contents"):
            fileops.move_file_or_directory(
                src = paths.join_paths(extract_dir, obj),
                dest = paths.join_paths(extract_dir, paths.get_filename_extension(obj).strip(".") + ".app"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Extract 3DS CIA file
def extract_3ds_cia(
    src_3ds_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    extract_tool = programs.find_tool_program("CtrTool")
    if not extract_tool:
        return False

    # Extract in a temporary directory, then move what was extracted
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        code = command.run_returncode_command(
            cmd = [
                extract_tool,
                "--contents", paths.join_paths(tmp_dir, "contents"),
                "--certs", paths.join_paths(tmp_dir, "00000000.cer"),
                "--tik", paths.join_paths(tmp_dir, "00000000.tik"),
                "--tmd", paths.join_paths(tmp_dir, "00000000.tmd"),
                src_3ds_file
            ],
            options = commandbase.create_command_options(
                blocking_processes = [extract_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False
        rename_3ds_cia_contents(tmp_dir, verbose, pretend_run, exit_on_failure)
        filebulk.move_contents(
            src = tmp_dir,
            dest = extract_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return os.path.exists(extract_dir) and not paths.is_directory_empty(extract_dir)

# CtrTool's printed description of a 3DS file as text; empty when CtrTool is not installed
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
        options = commandbase.create_command_options(
            blocking_processes = [print_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return output

# The value of the first well-formed "Title id:" line of the file info; empty when there is none
def get_3ds_title_id(file_info):
    for line in file_info.split("\n"):
        if line.startswith("Title id:"):
            line_tokens = line.split(":")
            if len(line_tokens) == 2:
                return line_tokens[1].strip()
    return ""

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
    app_titleid = get_3ds_title_id(file_info)
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
# Rom folders
######################################################

# The 3DS tool actions, in the order a flag set picks the one it names
THREEDS_ACTION_NAMES = [
    ("cia_to_cci", "Convert CIA to 3DS(CCI)"),
    ("cci_to_cia", "Convert 3DS(CCI) to CIA"),
    ("trim_cci", "Trim 3DS(CCI)"),
    ("untrim_cci", "Untrim 3DS(CCI)"),
    ("extract_cia", "Extract CIA"),
    ("info", "Print info"),
]

# The name of the first 3DS tool action set; None when none is
def get_3ds_action_name(
    cia_to_cci = False,
    cci_to_cia = False,
    trim_cci = False,
    untrim_cci = False,
    extract_cia = False,
    info = False):
    selected = {
        "cia_to_cci": cia_to_cci,
        "cci_to_cia": cci_to_cia,
        "trim_cci": trim_cci,
        "untrim_cci": untrim_cci,
        "extract_cia": extract_cia,
        "info": info}
    for action, name in THREEDS_ACTION_NAMES:
        if selected[action]:
            return name
    return None

# The files a 3DS rom converts to beside it, named without any .trim: its .cia, .3ds,
# .trim.3ds and its extract folder
def _get_3ds_output_paths(rom_file):
    rom_dir = paths.get_filename_directory(rom_file)
    rom_basename = paths.get_filename_basename(rom_file).replace(".trim", "")
    return {
        "cia": paths.join_paths(rom_dir, rom_basename + ".cia"),
        "3ds": paths.join_paths(rom_dir, rom_basename + ".3ds"),
        "trimmed_3ds": paths.join_paths(rom_dir, rom_basename + ".trim.3ds"),
        "extract_dir": paths.join_paths(rom_dir, rom_basename)}

# The first selected conversion a rom's suffix allows, as its function and output keyword
# arguments; (None, None) when none applies
def _get_3ds_conversion(rom_file, conversions, outputs):
    cia_to_cci, cci_to_cia, trim_cci, untrim_cci, extract_cia = conversions
    if cia_to_cci and rom_file.endswith(".cia"):
        return convert_3ds_cia_to_cci, {"dest_3ds_file": outputs["trimmed_3ds"]}
    if cci_to_cia and rom_file.endswith(".3ds"):
        return convert_3ds_cci_to_cia, {"dest_3ds_file": outputs["cia"]}
    if trim_cci and rom_file.endswith(".3ds") and ".trim" not in rom_file:
        return trim_3ds_cci, {"dest_3ds_file": outputs["trimmed_3ds"]}
    if untrim_cci and rom_file.endswith(".trim.3ds"):
        return untrim_3ds_cci, {"dest_3ds_file": outputs["3ds"]}
    if extract_cia and rom_file.endswith(".cia"):
        return extract_3ds_cia, {"extract_dir": outputs["extract_dir"]}
    return None, None

# Convert one rom by the first selected conversion its suffix allows, or else log its info when asked
def _process_3ds_rom(rom_file, conversions, info, flags):
    conversion, outputs = _get_3ds_conversion(rom_file, conversions, _get_3ds_output_paths(rom_file))
    if conversion:
        conversion(src_3ds_file = rom_file, **outputs, **flags)
    elif info:
        logger.log_info(get_3ds_file_info(src_3ds_file = rom_file, **flags))

# Convert, trim, untrim or extract every .cia and .3ds under input_path, each by the
# first selected action its suffix allows, or log CtrTool's info for each
def process_3ds_roms(
    input_path,
    cia_to_cci = False,
    cci_to_cia = False,
    trim_cci = False,
    untrim_cci = False,
    extract_cia = False,
    info = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    flags = {"verbose": verbose, "pretend_run": pretend_run, "exit_on_failure": exit_on_failure}
    conversions = (cia_to_cci, cci_to_cia, trim_cci, untrim_cci, extract_cia)
    for rom_file in paths.build_file_list_by_extensions(input_path, extensions = [".cia", ".3ds"]):
        _process_3ds_rom(rom_file, conversions, info, flags)
