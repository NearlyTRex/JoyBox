# Imports
from joybox import config
from joybox import presets
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "run_presets")
    parser.add_output_path_argument(description = "Destination directory passed to each run as `-o`; it must exist")
    parser.add_enum_argument(
        args = ("-r", "--preset_tool_type"),
        arg_type = config.PresetToolType,
        default = config.PresetToolType.BACKUP_TOOL,
        description = "JoyBox tool to run for each platform")
    parser.add_enum_argument(
        args = ("-g", "--preset_option_group_type"),
        arg_type = config.PresetOptionGroupType,
        required = True,
        description = "Preset group naming the platforms to run over")
    parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Pass `--skip_existing` on, so files already at the destination are skipped")
    parser.add_boolean_argument(args = ("-i", "--skip_identical"), description = "Pass `--skip_identical` on, so files already at the destination with the same content are skipped")
    parser.add_common_arguments()
    return parser

# Run the chosen tool, only backup_tool so far, once per subcategory of the preset group with the shared options
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get output path
    output_path = parser.get_output_path()

    # Run the preset tool over the group's platforms
    return presets.run_presets(
        preset_tool_type = args.preset_tool_type,
        preset_option_group_type = args.preset_option_group_type,
        output_path = output_path,
        skip_existing = args.skip_existing,
        skip_identical = args.skip_identical,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
