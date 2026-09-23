#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.decompiler as decompiler
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Open Ghidra with Python support, or run a PyGhidra script against a Ghidra project.",
    details = (
        "`LaunchProgram` (the default) starts the Ghidra GUI through PyGhidra (`python -m\n"
        "pyghidra -g`), so Python scripts can be used inside it. `RunScript` runs a PyGhidra\n"
        "script headless against an existing Ghidra project.\n"
        "\n"
        "Both use the JoyBox Python virtual environment and the Ghidra installed by\n"
        "`setup_tools` (its `lib` directory is passed as `GHIDRA_INSTALL_DIR`).\n"
        "\n"
        "A script can be run two ways. In preset mode, `--preset` and `--script` pick a\n"
        "project and script defined in `Shared/joybox/config/decompiler.py`, with paths\n"
        "relative to the preset's repository under `[UserData.Dirs] repositories_dir`, and the\n"
        "script's default arguments. In manual mode, give `--project_dir`, `--project_name`,\n"
        "`--program_name`, `--script_path` and `--script_name` yourself.\n"
        "\n"
        "The script is called as `python <script> <project_dir> <project_name> <program_name>\n"
        "[script_args]`. It runs with `-Djava.awt.headless=true` added to\n"
        "`JAVA_TOOL_OPTIONS`, so it never needs a display."),
    examples = [
        ("Open Ghidra with PyGhidra", "decompiler_tool"),
        ("List the presets", "decompiler_tool --list_presets"),
        ("List the scripts of one preset", "decompiler_tool --list_scripts --preset NocturneDecomp"),
        ("Run a preset script with its default arguments", "decompiler_tool -a RunScript --preset NocturneDecomp --script export_all"),
        ("Run a preset script with other arguments", "decompiler_tool -a RunScript --preset NocturneDecomp --script export_nocedit --script_args ~/annotations/nocedit"),
        ("Run a script by hand against a project", "decompiler_tool -a RunScript -r ~/Repositories/NocturneDecomp/projects -n NocturneEdit -g nocedit.exe --script_path ~/Repositories/NocturneDecomp/scripts/Python --script_name export_annotations.py"),
        ("Dry run without starting Python", "decompiler_tool -a RunScript --preset NocturneDecomp --script export_all -p -v"),
    ],
    notes = [
        "`--script_args` replaces the preset's default arguments, and is passed to the script as one argument, not split on spaces.",
        "Ghidra must be installed with `setup_tools -k Ghidra`, or the command reports that the installation was not found.",
        "`--list_presets` and `--list_scripts` exit without running anything; `--list_scripts` without `--preset` lists the scripts of every preset.",
    ],
    see_also = ["setup_tools", "claude_tool", "llm_chat"],
    section = "Development")
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
args = parser.parse_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # List presets
    if args.list_presets:
        logger.log_info("Available presets:")
        for preset_name, desc in decompiler.list_presets():
            logger.log_info("  %s - %s" % (preset_name, desc))
        return

    # List scripts
    if args.list_scripts:
        if args.preset:
            scripts = decompiler.list_preset_scripts(args.preset)
            if scripts is None:
                logger.log_error("Preset not found: %s" % args.preset)
                return
            logger.log_info("Available scripts for '%s':" % args.preset)
            for script_name, desc in scripts:
                logger.log_info("  %s - %s" % (script_name, desc))
        else:
            for preset_name, preset_desc in decompiler.list_presets():
                logger.log_info("%s:" % preset_name)
                for script_name, desc in decompiler.list_preset_scripts(preset_name):
                    logger.log_info("  %s - %s" % (script_name, desc))
        return

    # Launch program
    if args.action == config.DecompilerActionType.LAUNCH_PROGRAM:
        decompiler.launch_program(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        return

    # Run script
    if args.action == config.DecompilerActionType.RUN_SCRIPT:

        # Preset mode
        if args.preset:
            if not args.script:
                logger.log_error("--script is required when using --preset")
                logger.log_info("Use --list_scripts --preset %s to see available scripts" % args.preset)
                return
            decompiler.run_script_from_preset(
                preset_name = args.preset,
                script_name = args.script,
                script_args = args.script_args,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            return

        # Manual mode
        project_dir = parser.get_checked_path("project_dir")
        script_path = parser.get_checked_path("script_path")
        if not all([project_dir, args.project_name, args.program_name, script_path, args.script_name]):
            logger.log_error("Manual mode requires: --project_dir, --project_name, --program_name, --script_path, --script_name")
            logger.log_info("Or use preset mode with: --preset <name> --script <script>")
            logger.log_info("Use --list_presets to see available presets")
            return
        decompiler.run_script(
            project_dir = project_dir,
            project_name = args.project_name,
            program_name = args.program_name,
            script_path = script_path,
            script_name = args.script_name,
            script_args = args.script_args,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
