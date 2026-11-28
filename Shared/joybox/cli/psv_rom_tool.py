# Imports
from joybox import system
from joybox import playstation
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "psv_rom_tool")
    parser.add_input_path_argument(description = "A `.psv` file, or a directory searched recursively for them; must exist")
    parser.add_group("Actions")
    parser.add_boolean_argument(args = ("-s", "--strip"), description = "Strip each dump into `<name>_stripped.psv`")
    parser.add_boolean_argument(args = ("-u", "--unstrip"), description = "Rebuild each stripped dump from it and `<name>.psve` into `<name>_unstripped.psv`")
    parser.add_boolean_argument(args = ("-t", "--trim"), description = "Trim each dump into `<name>_trimmed.psv`")
    parser.add_boolean_argument(args = ("-n", "--untrim"), description = "Expand each trimmed dump to full size into `<name>_untrimmed.psv`")
    parser.add_boolean_argument(args = ("-e", "--verify"), description = "Check each dump with PSVTools without writing anything")
    parser.add_group("Behavior")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the source `.psv` after it is converted; ignored by `-e`")
    parser.add_common_arguments()
    return parser

# After a preview, strip, unstrip, trim, untrim or verify each Vita cartridge dump under the input
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Determine action
    action = playstation.get_psv_action_name(args.strip, args.unstrip, args.trim, args.untrim, args.verify)

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Action: %s" % action
    ]
    if args.delete_originals:
        details.append("Delete originals: %s" % args.delete_originals)
    if not prompts.confirm_preview(args.no_preview, "PSV ROM tool", details):
        return

    # Run the action on the psv files
    playstation.process_psv_files(
        input_path = input_path,
        action = action,
        delete_originals = args.delete_originals,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
