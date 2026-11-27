# Imports
from joybox import config
from joybox import system
from joybox import decompiler
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "decompiler_tool")
    parser.add_enum_argument(
        args = ("-a", "--action"),
        arg_type = config.DecompilerActionType,
        default = config.DecompilerActionType.LAUNCH_PROGRAM,
        description = "`LaunchProgram` opens the Ghidra GUI; `RunScript` runs a script headless")
    parser.add_group("Project (manual mode)")
    parser.add_string_argument(args = ("-n", "--project_name"), description = "Name of the Ghidra project inside `--project_dir`")
    parser.add_string_argument(args = ("-l", "--project_language"), default = "x86:LE:32:watcom", description = "Ghidra language id of the program; not passed to the script")
    parser.add_string_argument(args = ("-c", "--project_cspec"), default = "watcomcpp", description = "Ghidra compiler spec of the program; not passed to the script")
    parser.add_input_path_argument(args = ("-r", "--project_dir"), description = "Directory holding the Ghidra project; it must exist")
    parser.add_string_argument(args = ("-g", "--program_name"), description = "Program in the project to run the script on, e.g. `nocedit.exe`")
    parser.add_group("Preset mode")
    parser.add_string_argument(args = ("--preset",), description = "Preset name, e.g. `NocturneDecomp`; see `--list_presets`")
    parser.add_string_argument(args = ("--script",), description = "Script name within the preset, e.g. `export_all`; see `--list_scripts`")
    parser.add_group("Script (manual mode)")
    parser.add_input_path_argument(args = ("--script_path",), description = "Directory holding the script; it must exist")
    parser.add_string_argument(args = ("--script_name",), description = "Script filename inside `--script_path`, e.g. `export_annotations.py`")
    parser.add_string_argument(args = ("--script_args",), description = "Extra argument passed to the script after the program name; in preset mode it replaces the preset's defaults")
    parser.add_group("Listing")
    parser.add_boolean_argument(args = ("--list_presets",), description = "List the presets with their descriptions and exit")
    parser.add_boolean_argument(args = ("--list_scripts",), description = "List the scripts of `--preset`, or of every preset when omitted, and exit")
    parser.add_common_arguments()
    return parser

# List presets or scripts, open the Ghidra GUI through PyGhidra, or run a PyGhidra script headless from a preset or given paths
def main():

    # Parse arguments
    parser = build_parser()
    args = parser.parse_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # List, launch or run a script
    return decompiler.run_decompiler_action(
        action = args.action,
        preset_name = args.preset,
        preset_script_name = args.script,
        project_dir = parser.get_path("project_dir"),
        project_name = args.project_name,
        program_name = args.program_name,
        script_path = parser.get_path("script_path"),
        script_name = args.script_name,
        script_args = args.script_args,
        list_presets_only = args.list_presets,
        list_scripts_only = args.list_scripts,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
