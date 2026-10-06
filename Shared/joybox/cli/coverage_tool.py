# Imports
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.testcoverage as testcoverage
import joybox.logger as logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Measure the library's test coverage and report where it falls short.",
        details = (
            "Actions:\n"
            "\n"
            "- `run`: run the unit tests under coverage.py the way CI does (from the checkout,\n"
            "  `pytest -q -c Tests/pytest.ini Tests/unit`, with pyproject's `[tool.coverage]`\n"
            "  settings), then report. The data is kept in the cache's `Coverage` directory, not\n"
            "  the checkout.\n"
            "- `report`: report on the last measurement without running anything.\n"
            "\n"
            "The library report gives the overall figure against the floor CI enforces (read\n"
            "from `.github/workflows/ci.yml`), a table per area (`core` for top-level modules,\n"
            "otherwise the first package such as `cli` or `emulators`), the files missing the\n"
            "most statements, the functions no test runs at all, and the files with nothing run.\n"
            "\n"
            "With `-m`, the report covers one module instead: its untested line ranges and every\n"
            "function with untested lines, whether never or partly run. `--source` adds each of\n"
            "those functions' source with its untested lines marked `!!`, which is also a compact\n"
            "brief to attach to `llm_chat` when asking a model how to test them.\n"
            "\n"
            "Every number comes from coverage.py's own data; functions are found by parsing the\n"
            "source, and a line counts toward the innermost function that holds it."),
        examples = [
            ("Measure and report on the whole library", "coverage_tool run"),
            ("Report again on the last measurement", "coverage_tool report"),
            ("Show the 40 files missing the most", "coverage_tool report -n 40"),
            ("Detail one module", "coverage_tool report -m programs.py"),
            ("Detail one module with its untested source", "coverage_tool report -m collection/jsondata.py --source"),
            ("Save the report as Markdown", "coverage_tool report -o coverage.md"),
            ("Ask a local model how to test a module", "coverage_tool report -m programs.py --source -o brief.md && llm_chat --code -a brief.md"),
        ],
        notes = [
            "coverage.py comes with the dev extra, which the bootstrap's `python` component installs.",
            "`run` exits with an error when a test fails, after printing the report, since the numbers then reflect a broken run.",
            "`--integration` adds `Tests/integration`, whose tests need programs outside the process; CI does not run them, so its figure differs.",
            "A module name matches the end of a measured file's path, such as `programs.py` or `cli/backup_tool.py`.",
        ],
        see_also = ["llm_chat"],
        section = "Development")
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

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

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
