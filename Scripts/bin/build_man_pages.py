#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
repo_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
shared_folder = os.path.join(repo_folder, "Shared")
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.logger as logger
import joybox.manpage as manpage
import joybox.system as system

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Generate the command reference in Docs from every script's help text.",
    details = (
        "Runs each script in Scripts/bin up to the point where it parses its arguments and\n"
        "renders a page from the parser: the description, every option with its default and\n"
        "allowed values, and the details, examples, notes and see-also the script declares.\n"
        "The pages are never edited by hand, so the help text is the only thing to maintain.\n"
        "\n"
        "Scripts run against a throwaway home directory holding only the default JoyBox.ini,\n"
        "so nothing from your own configuration ends up in a default shown on a page."),
    examples = [
        ("Regenerate every page", "build_man_pages"),
        ("Fail if a page is out of date or a script's help text is incomplete", "build_man_pages --check"),
    ],
    notes = [
        "A page for a script that no longer exists is removed.",
        "`--check` exits non-zero and writes nothing, which makes it usable in a hook or CI.",
    ],
    see_also = ["setup_tools"],
    section = "Development")
parser.add_string_argument(
    args = ("-o", "--output_path"),
    description = "Directory to write the pages into, instead of Docs/reference/man in this checkout")
parser.add_string_argument(
    args = ("-s", "--scripts_path"),
    description = "Directory of scripts to document, instead of Scripts/bin in this checkout")
parser.add_boolean_argument(
    args = ("-k", "--check"),
    description = "Report out-of-date pages and incomplete help text without writing anything")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Resolve directories
    output_path = args.output_path or os.path.join(repo_folder, "Docs", "reference", "man")
    scripts_path = args.scripts_path or os.path.join(repo_folder, "Scripts", "bin")

    # Describe every script
    specs = manpage.describe_scripts(scripts_path, shared_folder)

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

# Start
if __name__ == "__main__":
    system.run_main(main)
