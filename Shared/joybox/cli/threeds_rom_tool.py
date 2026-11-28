# Imports
from joybox import system
from joybox.nintendo import threeds
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "threeds_rom_tool")
    parser.add_input_path_argument(description = "A `.cia` or `.3ds` file, or a directory searched recursively for them; must exist")
    parser.add_group("Actions")
    parser.add_boolean_argument(args = ("-a", "--cia_to_cci"), description = "Convert each CIA to a CCI written next to it")
    parser.add_boolean_argument(args = ("-b", "--cci_to_cia"), description = "Convert each `<name>.3ds` CCI to `<name>.cia`")
    parser.add_boolean_argument(args = ("-t", "--trim_cci"), description = "Trim each `<name>.3ds` CCI into `<name>.trim.3ds`")
    parser.add_boolean_argument(args = ("-u", "--untrim_cci"), description = "Restore each `<name>.trim.3ds` to full size as `<name>.3ds`")
    parser.add_boolean_argument(args = ("-e", "--extract_cia"), description = "Unpack each `<name>.cia` into a `<name>` folder next to it")
    parser.add_boolean_argument(args = ("-n", "--info"), description = "Print CtrTool's information for every CIA and CCI")
    parser.add_common_arguments()
    return parser

# After a preview, convert, trim, untrim, extract or inspect each 3DS CIA and CCI file under the input
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Determine action
    action = threeds.get_3ds_action_name(
        args.cia_to_cci, args.cci_to_cia, args.trim_cci, args.untrim_cci, args.extract_cia, args.info)

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Action: %s" % action
    ]
    if not prompts.confirm_preview(args.no_preview, "3DS ROM tool", details):
        return

    # Run the chosen actions on the roms
    threeds.process_3ds_roms(
        input_path = input_path,
        cia_to_cci = args.cia_to_cci, cci_to_cia = args.cci_to_cia, trim_cci = args.trim_cci,
        untrim_cci = args.untrim_cci, extract_cia = args.extract_cia, info = args.info,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
