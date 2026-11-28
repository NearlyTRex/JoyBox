# Imports
from joybox import config
from joybox import collection
from joybox import system
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "analyze_game_json_files")
    parser.add_enum_argument(
        args = ("-m", "--mode"),
        arg_type = config.AnalyzeModeType,
        default = config.AnalyzeModeType.ALL,
        description = "Which list to show: games with no files, unplayable games, or both")
    parser.add_common_arguments()
    return parser

# Log the games whose JSON file lists no files and those not marked playable, across every category; changes nothing
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Analyze json files
    collection.jsondata.analyze_game_json_files(
        mode = args.mode,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
