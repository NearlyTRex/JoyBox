# Imports
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import testcoverage
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "coverage_tool")
    parser.add_string_argument(
        args = ("action",),
        default = testcoverage.ACTION_REPORT,
        description = "Action to perform: `run` or `report`")
    parser.add_string_argument(
        args = ("-m", "--module"),
        description = "Report on this module alone, e.g. `programs.py` or `cli/backup_tool.py`")
    parser.add_integer_argument(
        args = ("-n", "--limit"),
        default = 20,
        description = "Rows in each ranked table of the library report")
    parser.add_string_argument(
        args = ("-o", "--output_file"),
        description = "Also write the report to this Markdown file")
    parser.add_boolean_argument(
        args = ("--source",),
        description = "With `-m`, include the source of each function with untested lines")
    parser.add_boolean_argument(
        args = ("--integration",),
        description = "With `run`, measure the integration tests as well")
    parser.add_common_arguments()
    return parser

# Run the unit tests under coverage and report, or report on the last measurement
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Run action
    return testcoverage.run_action(
        action = args.action,
        module = args.module,
        limit = args.limit,
        output_file = args.output_file,
        show_source = args.source,
        include_integration = args.integration,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
