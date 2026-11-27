# Imports
import os
import os.path
from joybox import arguments
from joybox import logger
from joybox import manpage
from joybox import system

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "build_man_pages")
    parser.add_string_argument(
        args = ("-o", "--output_path"),
        description = "Directory to write the pages into, instead of Docs/reference/man in this checkout")
    parser.add_string_argument(
        args = ("-s", "--project_path"),
        description = "pyproject.toml whose commands to document, instead of this checkout's")
    parser.add_boolean_argument(
        args = ("-k", "--check"),
        description = "Report out-of-date pages and incomplete help text without writing anything")
    parser.add_common_arguments()
    return parser

# Render a reference page from every console script's parser into Docs, reporting commands whose help text is incomplete
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Resolve directories
    shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    repo_folder = os.path.dirname(shared_folder)
    output_path = args.output_path or os.path.join(repo_folder, "Docs", "reference", "man")
    project_path = args.project_path or os.path.join(repo_folder, "pyproject.toml")

    # Describe every command
    specs = manpage.describe_commands(project_path, [shared_folder])

    # Report incomplete help text
    problems = []
    for tool_name, spec in specs.items():
        for problem in manpage.find_help_problems(tool_name, spec, specs.keys()):
            problems.append("%s: %s" % (tool_name, problem))
    for problem in problems:
        logger.log_warning(problem)

    # Render
    pages = manpage.render_all(specs)
    if args.check:
        stale, extra = manpage.find_stale_pages(pages, output_path)
        for filename in stale:
            logger.log_warning("Out of date: %s" % filename)
        for filename in extra:
            logger.log_warning("No longer generated: %s" % filename)
        return not (problems or stale or extra)

    # Write
    if args.pretend_run:
        stale, extra = manpage.find_stale_pages(pages, output_path)
    else:
        stale, extra = manpage.write_pages(pages, output_path)
    logger.log_info("Updated %d page(s), removed %d, in %s" % (len(stale), len(extra), output_path))
    return True

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
