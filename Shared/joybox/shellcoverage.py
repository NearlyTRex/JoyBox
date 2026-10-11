# Imports
import os
import re

# Local imports
import joybox.paths as paths
import joybox.serialization as serialization

###########################################################
# Shell coverage
#
# The shell under Bootstrap/ and install.sh runs where Python may not exist
# yet, so coverage.py never sees it. Tests run it with bash's xtrace sent to a
# trace file instead, and this measures those traces against the scripts.
#
# The unit is a statement, not a line. Bash reports a command that spans
# several lines under its first line or its last depending on the construct,
# so a statement counts as run when any traced line falls inside it.
###########################################################

# Where the measured scripts live, relative to the repository root
SCRIPT_ROOTS = ["Bootstrap", "install.sh"]
SCRIPT_EXTENSIONS = [".sh"]

# The environment variable naming the trace file a traced shell appends to
TRACE_VARIABLE = "JOYBOX_SHELL_TRACE"

# Sourced through BASH_ENV, so every non-interactive bash a test starts, and
# every bash those start, traces itself. A no-op when no trace file is named.
TRACE_HOOK = """if [ -n "${%s:-}" ]; then
    exec {__joybox_trace_fd}>>"$%s"
    BASH_XTRACEFD=$__joybox_trace_fd
    PS4='+${BASH_SOURCE[0]:-}:${LINENO}: '
    set -x
fi
""" % (TRACE_VARIABLE, TRACE_VARIABLE)

# One traced command: the + marks repeat once per level of nesting
TRACE_LINE = re.compile(r"^\++(?P<path>/[^:\n]*):(?P<line>\d+): ", re.MULTILINE)

###########################################################
# Statements
###########################################################

# Words that close or continue a construct without running anything
STRUCTURAL_WORDS = {"{", "}", "(", ")", "fi", "done", "esac", "else", "then", "do", ";;", ";&", ";;&"}

# What may follow a structural word on its line and still run nothing:
# redirections of the construct it closes, and case terminators
INERT_TAIL = re.compile(r"^(\s*(;;&|;;|;&|;|[0-9]*(>>|>&|<&|<<<|>|<)\s*\S+))*\s*$")

# A function header, with or without the keyword and the opening brace
FUNCTION_HEADER = re.compile(r"^(function\s+[\w:.-]+(\s*\(\))?|[\w:.-]+\s*\(\))\s*\{?\s*$")

# A case pattern opening its line, up to the parenthesis that ends it
CASE_PATTERN = re.compile(r"^\s*\(?(?P<pattern>([^()\\\s]|\\.|\s(?=[^)]*\)))+)\)")

# A here-document operator and its terminator, quoted or not
HEREDOC = re.compile(r"<<(?P<strip>-?)\s*(?P<quote>['\"]?)(?P<word>[\w.-]+)(?P=quote)")

# Check if a line holds nothing that runs
def is_inert_line(text):
    stripped = re.sub(r"(^|\s)#.*$", "", text).strip()
    if not stripped:
        return True
    if FUNCTION_HEADER.match(stripped):
        return True
    word = stripped.split()[0]
    for structural in sorted(STRUCTURAL_WORDS, key = len, reverse = True):
        if word.startswith(structural) and (len(word) == len(structural) or not word[len(structural)].isalnum()):
            return bool(INERT_TAIL.match(stripped[len(structural):]))
    return False

# Remove a case pattern from the start of a line inside a case
def strip_case_pattern(text):
    match = CASE_PATTERN.match(text)
    if not match:
        return text, False
    return text[match.end():], True

# The state carried from one line to the next: the open quote, how deeply
# parentheses nest, and the nesting levels at which a command substitution
# opened inside double quotes, so its closing parenthesis returns to them
def new_scan_state():
    return {"quote": None, "depth": 0, "quoted_substitutions": []}

# Scan one line of code, carrying quote and nesting state across lines
# Returns the here-documents the line opens and whether it ends in a way that
# continues the statement onto the next line.
def scan_line(text, state):
    heredocs = []
    index = 0
    code_end = len(text)
    while index < len(text):
        char = text[index]
        if state["quote"] == "'":
            if char == "'":
                state["quote"] = None
        elif char == "\\":
            index += 1
        elif state["quote"] == '"':
            if char == '"':
                state["quote"] = None
            elif text.startswith("$(", index):
                state["depth"] += 1
                state["quoted_substitutions"].append(state["depth"])
                state["quote"] = None
                index += 1
        elif char in ("'", '"'):
            state["quote"] = char
        elif char == "#" and (index == 0 or text[index - 1] in " \t;&|()"):
            code_end = index
            break
        elif char == "(":
            state["depth"] += 1
        elif char == ")" and state["depth"] > 0:
            if state["quoted_substitutions"] and state["quoted_substitutions"][-1] == state["depth"]:
                state["quoted_substitutions"].pop()
                state["quote"] = '"'
            state["depth"] -= 1
        elif text.startswith("<<", index) and not text.startswith("<<<", index):
            match = HEREDOC.match(text, index)
            if match and not match.group("word").isdigit():
                heredocs.append((match.group("word"), bool(match.group("strip"))))
                index = match.end() - 1
        index += 1
    code = text[:code_end].rstrip()
    continues = (
        state["quote"] is not None or state["depth"] > 0 or
        (code.endswith("\\") and not code.endswith("\\\\")) or
        code.endswith(("&&", "||", "|")))
    return heredocs, continues

# Find the statements of a script, as inclusive (first, last) line ranges
def find_statements(source):
    statements = []
    state = new_scan_state()
    case_depth = 0
    start = None
    heredocs = []
    for number, text in enumerate((source or "").split("\n"), start = 1):

        # A here-document body belongs to the statement that opened it
        if heredocs:
            word, strip = heredocs[0]
            if (text.lstrip("\t") if strip else text) == word:
                heredocs.pop(0)
            if start is None and statements:
                statements[-1] = (statements[-1][0], number)
            continue

        code = text
        if start is None:
            stripped = text.strip()
            if stripped.startswith("esac"):
                case_depth = max(0, case_depth - 1)
            elif case_depth:
                code, is_pattern = strip_case_pattern(text)
                if is_pattern and is_inert_line(code):
                    continue
            if is_inert_line(code):
                continue
            start = number
        opened, continues = scan_line(code, state)
        heredocs.extend(opened)
        if re.match(r"^\s*case\s.*\sin\s*(#.*)?$", text):
            case_depth += 1
        if not continues:
            statements.append((start, number))
            start = None
    return statements

###########################################################
# Traces
###########################################################

# Read the lines a trace says were run, per script
def parse_trace(text):
    hits = {}
    for match in TRACE_LINE.finditer(text or ""):
        path = os.path.normpath(match.group("path"))
        hits.setdefault(path, set()).add(int(match.group("line")))
    return hits

# Merge the hits of several traces
def merge_hits(*all_hits):
    merged = {}
    for hits in all_hits:
        for path, lines in hits.items():
            merged.setdefault(path, set()).update(lines)
    return merged

# Read every trace file in a directory
def read_traces(trace_dir):
    traces = []
    for trace_file in paths.build_file_list(trace_dir):
        traces.append(parse_trace(serialization.read_text_file(trace_file)))
    return merge_hits(*traces)

###########################################################
# Measuring
###########################################################

# Find the scripts to measure, relative to the repository root
def find_scripts(repo_dir):
    scripts = []
    for root in SCRIPT_ROOTS:
        found = paths.build_file_list_by_extensions(
            paths.join_paths(repo_dir, root), extensions = SCRIPT_EXTENSIONS)
        scripts.extend(os.path.relpath(script, repo_dir) for script in found)
    return sorted(scripts)

# Check if any line run falls inside a statement
def is_statement_run(statement, lines_run):
    first, last = statement
    return any(first <= line <= last for line in lines_run)

# Measure one script's statements against the lines run in it
def measure_script(source, lines_run):
    statements = find_statements(source)
    missed = [statement for statement in statements if not is_statement_run(statement, lines_run)]
    return {
        "statements": len(statements),
        "covered": len(statements) - len(missed),
        "missed": missed,
    }

# Measure every script against the traces in a directory
def measure(repo_dir, trace_dir):
    hits = read_traces(trace_dir)
    results = {}
    for script in find_scripts(repo_dir):
        absolute = os.path.normpath(paths.join_paths(repo_dir, script))
        source = serialization.read_text_file(absolute)
        results[script] = measure_script(source, hits.get(absolute, set()))
    return results

# Get the share of statements run, over every script
def get_total_percent(results):
    statements = sum(result["statements"] for result in results.values())
    if statements == 0:
        return 100.0
    return 100.0 * sum(result["covered"] for result in results.values()) / statements

# Get one script's share of statements run
def get_percent(result):
    if result["statements"] == 0:
        return 100.0
    return 100.0 * result["covered"] / result["statements"]

###########################################################
# Reporting
###########################################################

# Describe missed statements as compact line ranges
def format_missed(missed, limit = 8):
    spans = ["%d" % first if first == last else "%d-%d" % (first, last) for first, last in missed]
    if len(spans) > limit:
        spans = spans[:limit] + ["..."]
    return ", ".join(spans)

# Render the report, scripts least covered first
def render_report(results, floor = None):
    width = max([len(name) for name in results] + [len("Script")])
    lines = ["Shell coverage", ""]
    lines.append("%-*s  %5s  %5s  %6s  %s" % (width, "Script", "Stmts", "Miss", "Cover", "Missing"))
    ordered = sorted(results.items(), key = lambda item: (get_percent(item[1]), item[0]))
    for name, result in ordered:
        lines.append("%-*s  %5d  %5d  %5.1f%%  %s" % (
            width, name, result["statements"], len(result["missed"]),
            get_percent(result), format_missed(result["missed"])))
    total = get_total_percent(results)
    lines.append("")
    lines.append("Total: %.1f%%" % total)
    if floor is not None:
        lines.append("Floor: %.1f%% (%s)" % (floor, "met" if total >= floor else "NOT MET"))
    return "\n".join(lines)

# Check whether the scripts meet a floor
def meets_floor(results, floor):
    return floor is None or get_total_percent(results) >= floor
