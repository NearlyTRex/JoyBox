# Imports
import os
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import shellcoverage


###########################################################
# Statements
#
# A statement is the unit coverage counts, so what is and is not one decides
# every number in the report.
###########################################################

def statements(*lines):
    return shellcoverage.find_statements("\n".join(lines))


def test_each_simple_command_is_a_statement():
    assert statements("echo one", "echo two") == [(1, 1), (2, 2)]


def test_an_empty_script_has_no_statements():
    assert shellcoverage.find_statements(None) == []
    assert statements("") == []


@pytest.mark.parametrize("line", [
    "", "   ", "# a comment", "#!/bin/bash",
    "install() {", "function install {", "function install() {", "install()",
    "{", "}", "fi", "done", "esac", "else", "then", "do", ";;", ")",
    "fi # end of check", "done < /etc/hosts", "done <<< \"$list\"", "} > /dev/null 2>&1", "esac;",
])
def test_lines_that_run_nothing_are_not_statements(line):
    assert statements(line) == []


@pytest.mark.parametrize("line", [
    "else echo fallback", "then echo yes", "done | sort", "{ echo grouped; }",
    "(cd /tmp && ls)", "(( count += 1 ))", "do_something now", "if [ -n \"$x\" ]; then",
    "for item in a b; do", "while read -r line; do", "case \"$1\" in",
])
def test_lines_that_run_something_are_statements(line):
    assert statements(line) == [(1, 1)]


def test_a_backslash_continues_a_statement():
    assert statements("apt-get install \\", "    nginx \\", "    curl", "echo done") == [(1, 3), (4, 4)]


def test_an_escaped_backslash_ends_one():
    assert statements("echo \\\\", "echo next") == [(1, 1), (2, 2)]


@pytest.mark.parametrize("ending", ["&&", "||", "|"])
def test_a_trailing_operator_continues_a_statement(ending):
    assert statements("[ -f /etc/x ] %s" % ending, "    echo found") == [(1, 2)]


def test_a_quote_left_open_continues_a_statement():
    assert statements("echo 'one", "two'", "echo \"three", "four\"") == [(1, 2), (3, 4)]


def test_an_escaped_quote_does_not_open_one():
    assert statements("echo \\'", "echo \\\"") == [(1, 1), (2, 2)]


def test_open_parentheses_continue_a_statement():
    assert statements("packages=(", "    nginx", "    curl", ")", "echo done") == [(1, 4), (5, 5)]


def test_a_command_substitution_inside_quotes_closes_back_into_them():
    assert statements('echo "$(date', '    +%s) still quoted', 'done"', "echo next") == [(1, 3), (4, 4)]


def test_a_comment_hides_what_follows_it():
    assert statements("echo one # it's fine (really", "echo two") == [(1, 1), (2, 2)]


def test_a_hash_inside_a_word_is_not_a_comment():
    assert statements("echo ${#items} a#b '#' \"#\" (", ")") == [(1, 2)]


###########################################################
# Here-documents
###########################################################

def test_a_here_document_belongs_to_its_command():
    assert statements("cat > /etc/x <<EOF", "renderer: (", "it's", "EOF", "echo done") == [(1, 4), (5, 5)]


@pytest.mark.parametrize("operator", ["<<'EOF'", '<<"EOF"', "<< EOF"])
def test_a_quoted_or_spaced_terminator_is_recognised(operator):
    assert statements("cat %s" % operator, "body", "EOF", "echo done") == [(1, 3), (4, 4)]


def test_an_indented_terminator_ends_a_tab_stripping_here_document():
    assert statements("\tcat <<-EOF", "\t\tbody", "\tEOF", "echo done") == [(1, 3), (4, 4)]


def test_an_indented_terminator_does_not_end_a_plain_one():
    assert statements("cat <<EOF", "  EOF", "EOF", "echo done") == [(1, 3), (4, 4)]


def test_two_here_documents_on_one_line_are_read_in_order():
    assert statements("paste <<A <(cat) <<B", "a", "A", "b", "B", "echo done") == [(1, 5), (6, 6)]


def test_a_here_document_inside_a_continuing_statement_is_part_of_it():
    assert statements("cat <<EOF |", "body", "EOF", "    sort", "echo done") == [(1, 4), (5, 5)]


@pytest.mark.parametrize("line", ["echo $(( 1 << 2 ))", "read -r x <<< \"$value\"", "cat <<$marker"])
def test_shifts_here_strings_and_variable_markers_open_no_here_document(line):
    assert statements(line, "echo next") == [(1, 1), (2, 2)]


###########################################################
# Case statements
###########################################################

def test_a_case_pattern_on_its_own_runs_nothing():
    assert statements(
        'case "$1" in',
        "    install|setup)",
        "        echo installing",
        "        ;;",
        "    *)",
        "        echo unknown",
        "        ;;",
        "esac",
        "echo after") == [(1, 1), (3, 3), (6, 6), (9, 9)]


def test_a_case_pattern_with_its_command_on_the_line_is_a_statement():
    assert statements('case "$1" in', "    -h) echo help ;;", "    (-v) echo verbose ;;", "esac") == [(1, 1), (2, 2), (3, 3)]


def test_a_command_inside_a_case_arm_is_not_mistaken_for_a_pattern():
    assert statements('case "$1" in', "    a)", '        echo "$(date)"', "        ;;", "esac") == [(1, 1), (3, 3)]


def test_patterns_are_only_looked_for_inside_a_case():
    assert statements("esac", "value)") == [(2, 2)]


###########################################################
# Traces
###########################################################

def test_a_trace_gives_the_lines_run_per_script():
    trace = "+/repo/a.sh:3: echo one\n++/repo/b.sh:7: helper\n+/repo/a.sh:5: echo 'two\nlines'\n"

    assert shellcoverage.parse_trace(trace) == {"/repo/a.sh": {3, 5}, "/repo/b.sh": {7}}


def test_paths_are_normalised_and_relative_ones_ignored():
    trace = "+/repo/scripts/../scripts/common.sh:4: x\n+relative.sh:2: y\n"

    assert shellcoverage.parse_trace(trace) == {"/repo/scripts/common.sh": {4}}


def test_an_empty_trace_runs_nothing():
    assert shellcoverage.parse_trace(None) == {}


def test_hits_merge_across_traces():
    merged = shellcoverage.merge_hits({"/a.sh": {1}}, {"/a.sh": {2}, "/b.sh": {3}})

    assert merged == {"/a.sh": {1, 2}, "/b.sh": {3}}


def test_every_trace_in_a_directory_is_read(tmp_path):
    (tmp_path / "one.trace").write_text("+/a.sh:1: x\n")
    (tmp_path / "two.trace").write_text("+/a.sh:2: y\n")

    assert shellcoverage.read_traces(str(tmp_path)) == {"/a.sh": {1, 2}}


def test_the_hook_traces_a_real_bash_run(tmp_path):
    hook = tmp_path / "hook.sh"
    hook.write_text(shellcoverage.TRACE_HOOK)
    script = tmp_path / "script.sh"
    script.write_text("#!/bin/bash\nset -u\nif false; then\n    echo never\nfi\necho ran\n")
    trace = tmp_path / "run.trace"
    env = dict(os.environ, BASH_ENV = str(hook))
    env[shellcoverage.TRACE_VARIABLE] = str(trace)

    result = subprocess.run(["bash", str(script)], env = env, capture_output = True, text = True, check = False)

    assert result.stdout == "ran\n"
    assert result.stderr == ""
    measured = shellcoverage.measure_script(script.read_text(), shellcoverage.parse_trace(trace.read_text())[str(script)])
    assert measured["missed"] == [(4, 4)]


def test_the_hook_does_nothing_without_a_trace_file(tmp_path):
    hook = tmp_path / "hook.sh"
    hook.write_text(shellcoverage.TRACE_HOOK)
    env = {key: value for key, value in os.environ.items() if key != shellcoverage.TRACE_VARIABLE}
    env["BASH_ENV"] = str(hook)

    result = subprocess.run(["bash", "-c", "echo $-"], env = env, capture_output = True, text = True, check = False)

    assert "x" not in result.stdout


###########################################################
# Measuring
###########################################################

@pytest.fixture
def repo(tmp_path):
    (tmp_path / "Bootstrap" / "scripts").mkdir(parents = True)
    (tmp_path / "Bootstrap" / "scripts" / "setup.sh").write_text("echo one\necho two\n")
    (tmp_path / "Bootstrap" / "scripts" / "notes.txt").write_text("not a script\n")
    (tmp_path / "install.sh").write_text("echo install\n")
    (tmp_path / "Other.sh").write_text("echo elsewhere\n")
    return tmp_path


def test_scripts_are_found_under_the_measured_roots(repo):
    assert shellcoverage.find_scripts(str(repo)) == ["Bootstrap/scripts/setup.sh", "install.sh"]


def test_a_statement_runs_when_any_of_its_lines_did():
    assert shellcoverage.is_statement_run((3, 5), {5})
    assert not shellcoverage.is_statement_run((3, 5), {2, 6})


def test_a_script_is_measured_against_the_lines_run():
    measured = shellcoverage.measure_script("echo one\necho two\necho three\n", {2})

    assert measured == {"statements": 3, "covered": 1, "missed": [(1, 1), (3, 3)]}


def test_every_script_is_measured_against_the_traces(repo, tmp_path_factory):
    traces = tmp_path_factory.mktemp("traces")
    (traces / "run.trace").write_text("+%s:1: echo one\n" % (repo / "Bootstrap" / "scripts" / "setup.sh"))

    results = shellcoverage.measure(str(repo), str(traces))

    assert results["Bootstrap/scripts/setup.sh"]["covered"] == 1
    assert results["install.sh"]["missed"] == [(1, 1)]


def test_the_total_counts_statements_not_scripts():
    results = {
        "a.sh": {"statements": 9, "covered": 9, "missed": []},
        "b.sh": {"statements": 1, "covered": 0, "missed": [(1, 1)]},
    }

    assert shellcoverage.get_total_percent(results) == 90.0


def test_nothing_to_measure_counts_as_covered():
    assert shellcoverage.get_total_percent({}) == 100.0
    assert shellcoverage.get_percent({"statements": 0, "covered": 0, "missed": []}) == 100.0


###########################################################
# Reporting
###########################################################

RESULTS = {
    "install.sh": {"statements": 4, "covered": 4, "missed": []},
    "Bootstrap/common.sh": {"statements": 4, "covered": 2, "missed": [(3, 3), (7, 9)]},
}


def test_missed_statements_read_as_line_ranges():
    assert shellcoverage.format_missed([(3, 3), (7, 9)]) == "3, 7-9"


def test_a_long_list_of_misses_is_cut_short():
    assert shellcoverage.format_missed([(line, line) for line in range(1, 5)], limit = 2) == "1, 2, ..."


def test_the_report_lists_the_least_covered_script_first():
    report = shellcoverage.render_report(RESULTS)
    lines = report.splitlines()

    assert lines[3].startswith("Bootstrap/common.sh")
    assert "50.0%" in lines[3] and lines[3].endswith("3, 7-9")
    assert lines[4].startswith("install.sh")
    assert "Total: 75.0%" in report
    assert "Floor" not in report


@pytest.mark.parametrize("floor, verdict", [(75, "met"), (80, "NOT MET")])
def test_the_report_says_whether_the_floor_is_met(floor, verdict):
    report = shellcoverage.render_report(RESULTS, floor)

    assert report.endswith("Floor: %.1f%% (%s)" % (floor, verdict))


def test_the_floor_is_checked_against_the_total():
    assert shellcoverage.meets_floor(RESULTS, None)
    assert shellcoverage.meets_floor(RESULTS, 75)
    assert not shellcoverage.meets_floor(RESULTS, 75.1)
