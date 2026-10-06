# Imports
import ast
import os
import re
import sys

# Local imports
import joybox.command as command
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.paths as paths
import joybox.serialization as serialization
import joybox.terminal as terminal

###########################################################
# Locations
#
# The tests are measured the way CI measures them: from the repository root,
# so pyproject's [tool.coverage] settings apply and file names come out
# relative to it. The data is kept in the cache rather than the checkout.
###########################################################

PYTEST_CONFIG = "Tests/pytest.ini"
UNIT_TESTS = "Tests/unit"
INTEGRATION_TESTS = "Tests/integration"
LIBRARY_PREFIX = "Shared/joybox/"
CI_WORKFLOW = ".github/workflows/ci.yml"

# Get the repository the library lives in
def get_repo_dir():
    return os.path.normpath(environment.get_repo_root(expand = True))

# Get the directory measurements are kept in
def get_data_dir():
    return paths.join_paths(environment.get_cache_root_dir(), "Coverage")

# Get coverage.py's data file
def get_data_file():
    return paths.join_paths(get_data_dir(), "coverage.data")

# Get the JSON export of the data
def get_json_file():
    return paths.join_paths(get_data_dir(), "coverage.json")

###########################################################
# Measuring
###########################################################

# Check that coverage.py can be run by this interpreter
def is_coverage_available():
    output = command.run_output_command([sys.executable, "-m", "coverage", "--version"])
    return "Coverage.py" in (output or "")

# Build the command that runs the tests under coverage
def build_measure_command(data_file, include_integration = False):
    cmd = [sys.executable, "-m", "coverage", "run", "--data-file", data_file,
        "-m", "pytest", "-q", "-c", PYTEST_CONFIG, UNIT_TESTS]
    if include_integration:
        cmd.append(INTEGRATION_TESTS)
    return cmd

# Run the tests under coverage, returning pytest's exit code
def measure(repo_dir, data_file, include_integration = False, verbose = False, pretend_run = False, exit_on_failure = False):
    fileops.make_directory(os.path.dirname(data_file), verbose = verbose, pretend_run = pretend_run)
    return command.run_returncode_command(
        cmd = build_measure_command(data_file, include_integration),
        options = command.create_command_options(cwd = repo_dir),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Export the data as JSON, which carries every number the report needs
def export_json(repo_dir, data_file, json_file, verbose = False):
    code = command.run_returncode_command(
        cmd = [sys.executable, "-m", "coverage", "json", "--data-file", data_file, "-o", json_file, "-q"],
        options = command.create_command_options(cwd = repo_dir),
        verbose = verbose)
    return code == 0

# Read the coverage floor CI enforces, or None when there is none
def read_ci_floor(repo_dir):
    text = serialization.read_text_file(paths.join_paths(repo_dir, CI_WORKFLOW)) or ""
    match = re.search(r"coverage-fail-under:\s*[\"']?(\d+(?:\.\d+)?)", text)
    return float(match.group(1)) if match else None

###########################################################
# Analysis
###########################################################

# Normalise a file name from the data to forward slashes
def normalize_name(name):
    return name.replace("\\", "/")

# Get the area a file belongs to: its first package under the library, or
# "core" for a module at the top
def get_area(name):
    relative = normalize_name(name)
    if relative.startswith(LIBRARY_PREFIX):
        relative = relative[len(LIBRARY_PREFIX):]
    parts = relative.split("/")
    return parts[0] if len(parts) > 1 else "core"

# Get the share of statements and branches run, the way coverage.py counts it
def get_percent(summary):
    total = summary.get("num_statements", 0) + summary.get("num_branches", 0)
    if total == 0:
        return 100.0
    covered = summary.get("covered_lines", 0) + summary.get("covered_branches", 0)
    return 100.0 * covered / total

# Add one summary's counts into another
SUMMED_FIELDS = (
    "num_statements", "missing_lines", "covered_lines",
    "num_branches", "covered_branches", "num_partial_branches")
def add_summary(total, summary):
    for field in SUMMED_FIELDS:
        total[field] = total.get(field, 0) + summary.get(field, 0)
    return total

# Total the files of each area, most missed first
def summarize_areas(files):
    areas = {}
    for name, entry in files.items():
        area = areas.setdefault(get_area(name), {"area": get_area(name), "files": 0})
        area["files"] += 1
        add_summary(area, entry["summary"])
    for area in areas.values():
        area["percent"] = get_percent(area)
    return sorted(areas.values(), key = lambda a: (-a["missing_lines"], a["area"]))

# Find the functions in a source file and what of each was run
# Each statement line counts toward the innermost function whose body holds
# it, so a nested function's lines are not also its parent's. A def line is
# run when its enclosing scope is, so it belongs to that scope, not the body.
def find_functions(source, executed_lines, missing_lines):
    spans = []
    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                spans.append({"name": name, "line": child.lineno,
                    "body_start": child.body[0].lineno, "end": child.end_lineno})
                visit(child, name + ".")
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")
            else:
                visit(child, prefix)
    visit(ast.parse(source), "")
    for span in spans:
        span["statements"] = 0
        span["missing_lines"] = []
    missing = set(missing_lines)
    for line in sorted(set(executed_lines) | missing):
        holders = [s for s in spans if s["body_start"] <= line <= s["end"]]
        if not holders:
            continue
        owner = max(holders, key = lambda s: s["body_start"])
        owner["statements"] += 1
        if line in missing:
            owner["missing_lines"].append(line)
    functions = []
    for span in sorted(spans, key = lambda s: s["line"]):
        if span["statements"]:
            functions.append({"name": span["name"], "line": span["line"],
                "statements": span["statements"], "missing_lines": span["missing_lines"]})
    return functions

# Check whether none of a function's statements ran
def is_never_run(function):
    return function["statements"] > 0 and len(function["missing_lines"]) == function["statements"]

# Find the functions with untested lines in every file that has some
def find_untested_functions(files, repo_dir):
    found = {}
    for name, entry in files.items():
        if not entry.get("missing_lines"):
            continue
        source = serialization.read_text_file(paths.join_paths(repo_dir, name))
        if source is None:
            continue
        try:
            functions = find_functions(source, entry.get("executed_lines", []), entry["missing_lines"])
        except SyntaxError:
            continue
        found[name] = [f for f in functions if f["missing_lines"]]
    return found

# Collapse sorted untested lines into ranges, joining two lines when no line
# that ran sits between them
def format_line_ranges(missing_lines, executed_lines):
    executed = sorted(executed_lines)
    ranges = []
    for line in sorted(missing_lines):
        if ranges and not any(ranges[-1][1] < run < line for run in executed):
            ranges[-1][1] = line
        else:
            ranges.append([line, line])
    return ", ".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in ranges)

# Find the one file a module name refers to, matching the end of its path
# Returns (name, candidates): the name when exactly one file matches.
def find_file(files, module):
    wanted = normalize_name(module)
    if not wanted.endswith(".py"):
        wanted += ".py"
    names = {normalize_name(name): name for name in files}
    if wanted in names:
        return names[wanted], [names[wanted]]
    matches = sorted(name for norm, name in names.items() if norm.endswith("/" + wanted))
    return (matches[0] if len(matches) == 1 else None), matches

###########################################################
# Report
###########################################################

# Format a percentage the way coverage.py rounds it for display
def format_percent(value):
    return "%.1f%%" % value

# Format a whole number with separators
def format_count(value):
    return "{:,}".format(value)

# List names for a table cell, at most a few before a count of the rest
NAMES_PER_CELL = 8
def list_names(names):
    shown = ", ".join("`%s`" % name for name in names[:NAMES_PER_CELL])
    if len(names) > NAMES_PER_CELL:
        shown += " and %d more" % (len(names) - NAMES_PER_CELL)
    return shown

# Render a Markdown table
def render_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return lines

# Render the report for the whole library
def render_report(results, untested, ci_floor = None, limit = 20, tests_passed = None):
    files = results["files"]
    totals = results["totals"]
    percent = totals.get("percent_covered", get_percent(totals))
    missed_branches = totals.get("num_branches", 0) - totals.get("covered_branches", 0)
    measured = len(files)
    complete = sum(1 for e in files.values() if not e["summary"]["missing_lines"] and not e["summary"].get("missing_branches"))
    below_half = sum(1 for e in files.values() if get_percent(e["summary"]) < 50)
    nothing_run = sorted(n for n, e in files.items() if e["summary"]["num_statements"] and not e["summary"]["covered_lines"])
    functions = [(name, f) for name, found in untested.items() for f in found]
    never_run = [(name, f) for name, f in functions if is_never_run(f)]

    # Summary
    lines = ["# Test coverage of %s" % LIBRARY_PREFIX.rstrip("/"), ""]
    timestamp = results.get("meta", {}).get("timestamp")
    if timestamp:
        lines.append("Measured %s." % timestamp.split(".")[0].replace("T", " "))
        lines.append("")
    lines.append("- **Overall: %s.** %s of %s statements are never run, and %s of %s branch outcomes never taken." % (
        format_percent(percent),
        format_count(totals["missing_lines"]), format_count(totals["num_statements"]),
        format_count(missed_branches), format_count(totals.get("num_branches", 0))))
    if ci_floor is not None:
        margin = percent - ci_floor
        verdict = "clears it by %.1f points" % margin if margin >= 0 else "**falls %.1f points short**" % -margin
        lines.append("- **CI floor: %s**; this %s." % (format_percent(ci_floor), verdict))
    if tests_passed is not None:
        lines.append("- **Tests:** %s." % ("all passed" if tests_passed else "**some failed**, so these numbers reflect a broken run"))
    lines.append("- **Files:** %d measured, %d fully covered, %d below 50%%, %d with nothing run." % (
        measured, complete, below_half, len(nothing_run)))
    lines.append("- **Functions:** %d have untested lines; %d of them never run at all." % (
        len(functions), len(never_run)))

    # Areas
    lines += ["", "## By area", ""]
    lines += render_table(
        ["Area", "Files", "Statements", "Missed", "Branches", "Partial", "Cover"],
        [(a["area"], a["files"], format_count(a["num_statements"]), format_count(a["missing_lines"]),
          format_count(a["num_branches"]), format_count(a["num_partial_branches"]), format_percent(a["percent"]))
         for a in summarize_areas(files)])

    # Files missing the most
    ranked = sorted(files.items(), key = lambda item: (-item[1]["summary"]["missing_lines"], item[0]))
    ranked = [(n, e) for n, e in ranked if e["summary"]["missing_lines"]][:limit]
    if ranked:
        never_by_file = {}
        for name, f in never_run:
            never_by_file[name] = never_by_file.get(name, 0) + 1
        lines += ["", "## Files missing the most (top %d)" % len(ranked), ""]
        lines += render_table(
            ["File", "Area", "Missed", "Partial", "Cover", "Never-run functions"],
            [(normalize_name(n), get_area(n), e["summary"]["missing_lines"], e["summary"]["num_partial_branches"],
              format_percent(get_percent(e["summary"])), never_by_file.get(n, 0)) for n, e in ranked])

    # Never-run functions
    if never_run:
        by_file = {}
        for name, f in never_run:
            by_file.setdefault(name, []).append(f)
        ordered = sorted(by_file.items(), key = lambda item: (-len(item[1]), item[0]))[:limit]
        lines += ["", "## Functions never run (top %d files)" % len(ordered), ""]
        lines += render_table(
            ["File", "Count", "Functions"],
            [(normalize_name(n), len(fs), list_names([f["name"] for f in fs])) for n, fs in ordered])

    # Files with nothing run
    if nothing_run:
        lines += ["", "## Files with nothing run", ""]
        lines += ["- `%s`" % normalize_name(n) for n in nothing_run[:limit]]
        if len(nothing_run) > limit:
            lines.append("- ... and %d more" % (len(nothing_run) - limit))
    return "\n".join(lines) + "\n"

# Render the report for one module, optionally with the source of each
# function that has untested lines, those lines marked with "!!"
def render_module_report(name, entry, functions, source = None):
    summary = entry["summary"]
    lines = ["# Test coverage of %s" % normalize_name(name), ""]
    lines.append("- **Cover: %s.** %d of %d statements not run; %d of %d branches partly taken." % (
        format_percent(get_percent(summary)), summary["missing_lines"], summary["num_statements"],
        summary.get("num_partial_branches", 0), summary.get("num_branches", 0)))
    if not entry.get("missing_lines"):
        lines.append("- Every statement is run by the tests.")
        return "\n".join(lines) + "\n"
    lines.append("- **Untested lines:** %s" % format_line_ranges(entry["missing_lines"], entry.get("executed_lines", [])))
    untested = sorted((f for f in functions if f["missing_lines"]), key = lambda f: (-len(f["missing_lines"]), f["line"]))
    if untested:
        lines += ["", "## Functions with untested lines", ""]
        lines += render_table(
            ["Function", "Line", "Statements", "Untested", "Status"],
            [("`%s`" % f["name"], f["line"], f["statements"], len(f["missing_lines"]),
              "never run" if is_never_run(f) else "partly run") for f in untested])
    if source is not None and untested:
        source_lines = source.splitlines()
        lines += ["", "## Source of untested functions", "",
            "Lines marked `!!` are never run by the tests.", ""]
        for f in untested:
            span = find_span(source, f["line"])
            missing = set(f["missing_lines"])
            lines += ["### %s" % f["name"], "", "```python"]
            for number in range(span[0], span[1] + 1):
                lines.append("%4d %s %s" % (number, "!!" if number in missing else "  ", source_lines[number - 1]))
            lines += ["```", ""]
    return "\n".join(lines).rstrip("\n") + "\n"

# Find the first and last line of the function defined on a line
def find_span(source, def_line):
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno == def_line:
            return (node.lineno, node.end_lineno)
    return (def_line, def_line)

###########################################################
# Action
###########################################################

# Actions
ACTION_RUN = "run"
ACTION_REPORT = "report"
ACTIONS = [ACTION_RUN, ACTION_REPORT]

# Measure (for "run") and report on the library or one module of it
# Returns False when anything fails, including a test, so the exit status
# says whether the numbers come from a clean run.
def run_action(
    action = ACTION_REPORT,
    module = None,
    limit = 20,
    output_file = None,
    show_source = False,
    include_integration = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if action not in ACTIONS:
        logger.log_error("Unknown action '%s'. Available: %s" % (action, ", ".join(ACTIONS)))
        return False
    repo_dir = get_repo_dir()
    if not paths.does_path_exist(paths.join_paths(repo_dir, "pyproject.toml")):
        logger.log_error("No JoyBox checkout at %s" % repo_dir)
        return False
    data_file = get_data_file()
    json_file = get_json_file()

    # Measure
    tests_passed = None
    if action == ACTION_RUN:
        if not pretend_run and not is_coverage_available():
            logger.log_error("coverage.py is not installed in this venv; it comes with the dev extra (pip install -e .[dev])")
            return False
        logger.log_info("Running the tests under coverage in %s" % repo_dir)
        code = measure(repo_dir, data_file, include_integration,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        if pretend_run:
            return True
        tests_passed = code == 0
        if not tests_passed:
            logger.log_warning("Some tests failed (exit code %d)" % code)

    # Load
    if not paths.does_path_exist(data_file):
        logger.log_error("No coverage data at %s; measure it first with the run action" % data_file)
        return False
    if not export_json(repo_dir, data_file, json_file, verbose = verbose):
        logger.log_error("Could not export the coverage data")
        return False
    results = serialization.read_json_file(json_file)
    if not results or "files" not in results:
        logger.log_error("Could not read %s" % json_file)
        return False

    # Render
    if module:
        name, matches = find_file(results["files"], module)
        if not name:
            if matches:
                logger.log_error("'%s' matches several files: %s" % (module, ", ".join(matches)))
            else:
                logger.log_error("No measured file matches '%s'" % module)
            return False
        entry = results["files"][name]
        source = serialization.read_text_file(paths.join_paths(repo_dir, name)) or ""
        functions = find_functions(source, entry.get("executed_lines", []), entry.get("missing_lines", []))
        report = render_module_report(name, entry, functions, source if show_source else None)
    else:
        untested = find_untested_functions(results["files"], repo_dir)
        report = render_report(results, untested, read_ci_floor(repo_dir), limit, tests_passed)

    # Output
    terminal.write(report)
    if output_file:
        if not serialization.write_text_file(output_file, report, verbose = verbose):
            logger.log_error("Could not write %s" % output_file)
            return False
        logger.log_info("Report written to %s" % output_file)
    return tests_passed is not False
