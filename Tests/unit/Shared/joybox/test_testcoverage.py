# Imports
import json
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import testcoverage


###########################################################
# Test coverage report
#
# Every number in the report has to be coverage.py's own: local models asked
# to count untested lines got them wrong, so the report is what does the
# counting. These tests pin how lines are attributed to functions and how the
# figures are totalled and ranked.
###########################################################

SOURCE = """def used(x):
    if x:
        return 1
    return 2

def unused():
    a = 1
    return a

class Thing:
    def method(self):
        def inner():
            return 3
        return inner()
"""
EXECUTED = [1, 2, 3, 6, 10, 11]
MISSING = [4, 7, 8, 12, 13, 14]


def functions_by_name():
    return {f["name"]: f for f in testcoverage.find_functions(SOURCE, EXECUTED, MISSING)}


###########################################################
# Functions
###########################################################

def test_a_partly_run_function_counts_its_body_only():
    # The def line runs at import, so it belongs to the module, not the function.
    used = functions_by_name()["used"]

    assert (used["line"], used["statements"], used["missing_lines"]) == (1, 3, [4])
    assert not testcoverage.is_never_run(used)


def test_a_function_whose_body_never_ran_is_never_run():
    assert testcoverage.is_never_run(functions_by_name()["unused"])


def test_methods_and_nested_functions_are_qualified_and_counted_once():
    functions = functions_by_name()

    # The nested def statement is the method's; the nested body is inner's
    assert functions["Thing.method"]["missing_lines"] == [12, 14]
    assert functions["Thing.method.inner"]["missing_lines"] == [13]
    assert sum(f["statements"] for f in functions.values()) == 3 + 2 + 2 + 1


def test_functions_come_back_in_source_order():
    assert list(functions_by_name()) == ["used", "unused", "Thing.method", "Thing.method.inner"]


def test_module_level_lines_belong_to_no_function():
    functions = testcoverage.find_functions("x = 1\ny = 2\n", [1], [2])

    assert functions == []


###########################################################
# Line ranges
###########################################################

def test_untested_lines_join_across_lines_that_are_not_statements():
    # 12 and 14 are split only by 13, which is not a statement
    assert testcoverage.format_line_ranges([7, 8, 12, 14], [1, 2, 3, 6, 10, 11]) == "7-8, 12-14"


def test_a_line_that_ran_splits_the_ranges():
    assert testcoverage.format_line_ranges([4, 7, 8], [1, 5]) == "4, 7-8"


###########################################################
# Areas and percentages
###########################################################

def summary(statements, missed, branches = 0, covered_branches = 0, partial = 0):
    return {"num_statements": statements, "missing_lines": missed, "covered_lines": statements - missed,
        "num_branches": branches, "covered_branches": covered_branches,
        "num_partial_branches": partial, "missing_branches": branches - covered_branches}


def entry(statements, missed, **kwargs):
    return {"summary": summary(statements, missed, **kwargs), "executed_lines": [], "missing_lines": []}


@pytest.mark.parametrize("name,area", [
    ("Shared/joybox/programs.py", "core"),
    ("Shared/joybox/cli/backup_tool.py", "cli"),
    ("Shared/joybox/bootstrap/installers/installer_node.py", "bootstrap"),
    ("Shared\\joybox\\emulators\\dolphin.py", "emulators"),
])
def test_a_file_belongs_to_its_first_package(name, area):
    assert testcoverage.get_area(name) == area


def test_the_percentage_counts_branches_like_coverage_py():
    # (6 lines + 2 branches run) of (10 + 4)
    assert testcoverage.get_percent(summary(10, 4, branches = 4, covered_branches = 2)) == pytest.approx(100 * 8 / 14)


def test_nothing_to_measure_is_fully_covered():
    assert testcoverage.get_percent(summary(0, 0)) == 100.0


def test_areas_are_totalled_and_ranked_by_what_they_miss():
    files = {
        "Shared/joybox/a.py": entry(10, 1),
        "Shared/joybox/b.py": entry(10, 2),
        "Shared/joybox/cli/c.py": entry(20, 15),
    }

    areas = testcoverage.summarize_areas(files)

    assert [(a["area"], a["files"], a["num_statements"], a["missing_lines"]) for a in areas] == [
        ("cli", 1, 20, 15), ("core", 2, 20, 3)]
    assert areas[1]["percent"] == pytest.approx(85.0)


###########################################################
# Finding a module
###########################################################

FILES = {name: None for name in [
    "Shared/joybox/programs.py",
    "Shared/joybox/cli/backup_tool.py",
    "Shared/joybox/backup_tool.py",
]}


@pytest.mark.parametrize("module,expected", [
    ("programs.py", "Shared/joybox/programs.py"),
    ("programs", "Shared/joybox/programs.py"),
    ("cli/backup_tool.py", "Shared/joybox/cli/backup_tool.py"),
    ("Shared/joybox/backup_tool.py", "Shared/joybox/backup_tool.py"),
])
def test_a_module_matches_the_end_of_a_path(module, expected):
    assert testcoverage.find_file(FILES, module)[0] == expected


def test_an_ambiguous_module_names_every_candidate():
    name, matches = testcoverage.find_file(FILES, "backup_tool.py")

    assert name is None
    assert matches == ["Shared/joybox/backup_tool.py", "Shared/joybox/cli/backup_tool.py"]


def test_a_partial_file_name_does_not_match():
    assert testcoverage.find_file(FILES, "grams.py") == (None, [])


###########################################################
# CI floor
###########################################################

@pytest.mark.parametrize("text,floor", [
    ('      coverage-fail-under: "82"\n', 82.0),
    ("      coverage-fail-under: 83.5\n", 83.5),
    ("jobs: {}\n", None),
])
def test_the_ci_floor_is_read_from_the_workflow(tmp_path, text, floor):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents = True)
    workflow.write_text(text)

    assert testcoverage.read_ci_floor(str(tmp_path)) == floor


def test_no_workflow_means_no_floor(tmp_path):
    assert testcoverage.read_ci_floor(str(tmp_path)) is None


###########################################################
# Measuring
###########################################################

def test_the_unit_tests_are_measured_the_way_ci_runs_them():
    cmd = testcoverage.build_measure_command("/cache/coverage.data")

    assert cmd[:6] == [sys.executable, "-m", "coverage", "run", "--data-file", "/cache/coverage.data"]
    assert cmd[6:] == ["-m", "pytest", "-q", "-c", "Tests/pytest.ini", "Tests/unit"]


def test_integration_tests_are_added_when_asked():
    assert testcoverage.build_measure_command("d", include_integration = True)[-2:] == ["Tests/unit", "Tests/integration"]


def test_measuring_runs_from_the_repository(recording_command, tmp_path):
    testcoverage.measure("/repo", str(tmp_path / "Coverage" / "coverage.data"))

    assert recording_command.only()[2:4] == ["coverage", "run"]
    assert recording_command.options().get_cwd() == "/repo"
    assert (tmp_path / "Coverage").is_dir()


###########################################################
# Library report
###########################################################

def results():
    mod = dict(entry(7, 6, branches = 2, covered_branches = 1, partial = 1), executed_lines = EXECUTED, missing_lines = MISSING)
    files = {
        "Shared/joybox/mod.py": mod,
        "Shared/joybox/done.py": entry(5, 0),
        "Shared/joybox/cli/tool.py": dict(entry(4, 4), missing_lines = [1, 2, 3, 4]),
    }
    totals = summary(16, 10, branches = 2, covered_branches = 1, partial = 1)
    totals["percent_covered"] = testcoverage.get_percent(totals)
    return {"meta": {"timestamp": "2026-10-04T17:51:08.123"}, "files": files, "totals": totals}


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "Shared" / "joybox" / "cli").mkdir(parents = True)
    (tmp_path / "Shared" / "joybox" / "mod.py").write_text(SOURCE)
    (tmp_path / "Shared" / "joybox" / "cli" / "tool.py").write_text("x = 1\n")
    return tmp_path


def render(repo, **kwargs):
    data = results()
    untested = testcoverage.find_untested_functions(data["files"], str(repo))
    return testcoverage.render_report(data, untested, **kwargs)


def test_the_summary_gives_the_overall_figures(repo):
    report = render(repo, ci_floor = 50.0)

    assert "Measured 2026-10-04 17:51:08." in report
    assert "**Overall: 38.9%.** 10 of 16 statements are never run, and 1 of 2 branch outcomes never taken." in report
    assert "**Files:** 3 measured, 1 fully covered, 2 below 50%, 1 with nothing run." in report
    assert "**Functions:** 4 have untested lines; 3 of them never run at all." in report


def test_the_ci_floor_is_compared(repo):
    assert "falls 11.1 points short" in render(repo, ci_floor = 50.0)
    assert "clears it by 8.9 points" in render(repo, ci_floor = 30.0)
    assert "CI floor" not in render(repo)


def test_a_failed_test_run_is_called_out(repo):
    assert "some failed" in render(repo, tests_passed = False)
    assert "all passed" in render(repo, tests_passed = True)
    assert "**Tests:**" not in render(repo)


def test_files_are_ranked_by_what_they_miss_and_capped(repo):
    report = render(repo, limit = 1)

    assert "## Files missing the most (top 1)" in report
    assert "| Shared/joybox/mod.py | core | 6 | 1 |" in report
    assert "| Shared/joybox/cli/tool.py | cli |" not in report


def test_never_run_functions_are_listed_by_file(repo):
    assert "| Shared/joybox/mod.py | 3 | `unused`, `Thing.method`, `Thing.method.inner` |" in render(repo)


def test_a_long_list_of_names_is_cut_short():
    names = ["f%d" % i for i in range(10)]

    assert testcoverage.list_names(names).endswith("`f7` and 2 more")


def test_files_with_nothing_run_are_listed(repo):
    assert "## Files with nothing run\n\n- `Shared/joybox/cli/tool.py`" in render(repo)


###########################################################
# Module report
###########################################################

def module_report(**kwargs):
    data = results()["files"]["Shared/joybox/mod.py"]
    functions = testcoverage.find_functions(SOURCE, EXECUTED, MISSING)
    return testcoverage.render_module_report("Shared/joybox/mod.py", data, functions, **kwargs)


def test_a_module_report_ranks_its_functions_by_untested_lines():
    report = module_report()

    assert "- **Untested lines:** 4, 7-8, 12-14" in report
    rows = [line for line in report.splitlines() if line.startswith("| `")]
    assert rows == [
        "| `unused` | 6 | 2 | 2 | never run |",
        "| `Thing.method` | 11 | 2 | 2 | never run |",
        "| `used` | 1 | 3 | 1 | partly run |",
        "| `Thing.method.inner` | 12 | 1 | 1 | never run |",
    ]
    assert "## Source" not in report


def test_a_module_report_can_carry_the_marked_source():
    report = module_report(source = SOURCE)

    assert "### unused\n\n```python\n   6    def unused():\n   7 !!     a = 1\n" in report
    assert "   3            return 1\n   4 !!     return 2\n```" in report


def test_a_fully_covered_module_says_so():
    report = testcoverage.render_module_report("Shared/joybox/done.py", entry(5, 0), [])

    assert "Every statement is run by the tests." in report


###########################################################
# Action
###########################################################

@pytest.fixture
def action(repo, tmp_path, monkeypatch):
    (repo / "pyproject.toml").write_text("")
    data_dir = tmp_path / "cache"
    data_dir.mkdir()
    state = {"measured": [], "code": 0, "written": []}
    monkeypatch.setattr(testcoverage, "get_repo_dir", lambda: str(repo))
    monkeypatch.setattr(testcoverage, "get_data_file", lambda: str(data_dir / "coverage.data"))
    monkeypatch.setattr(testcoverage, "get_json_file", lambda: str(data_dir / "coverage.json"))
    monkeypatch.setattr(testcoverage, "is_coverage_available", lambda: True)
    monkeypatch.setattr(testcoverage.terminal, "write", state["written"].append)

    def measure(repo_dir, data_file, include_integration = False, **kwargs):
        state["measured"].append((repo_dir, include_integration, kwargs.get("pretend_run")))
        if not kwargs.get("pretend_run"):
            open(data_file, "w").close()
        return state["code"]

    def export_json(repo_dir, data_file, json_file, verbose = False):
        with open(json_file, "w") as handle:
            json.dump(results(), handle)
        return True

    monkeypatch.setattr(testcoverage, "measure", measure)
    monkeypatch.setattr(testcoverage, "export_json", export_json)
    state["data_file"] = str(data_dir / "coverage.data")
    return state


def test_run_measures_then_reports(action, repo):
    assert testcoverage.run_action(testcoverage.ACTION_RUN, include_integration = True) is True
    assert action["measured"] == [(str(repo), True, False)]
    assert "# Test coverage of Shared/joybox" in action["written"][0]
    assert "all passed" in action["written"][0]


def test_a_failed_test_still_reports_but_fails(action):
    action["code"] = 1

    assert testcoverage.run_action(testcoverage.ACTION_RUN) is False
    assert "some failed" in action["written"][0]


def test_a_pretend_run_measures_nothing_and_reports_nothing(action):
    assert testcoverage.run_action(testcoverage.ACTION_RUN, pretend_run = True) is True
    assert action["measured"][0][2] is True
    assert action["written"] == []


def test_report_needs_an_earlier_measurement(action):
    assert testcoverage.run_action(testcoverage.ACTION_REPORT) is False
    assert action["measured"] == []


def test_report_uses_the_last_measurement(action):
    open(action["data_file"], "w").close()

    assert testcoverage.run_action(testcoverage.ACTION_REPORT) is True
    assert action["measured"] == []
    assert "**Tests:**" not in action["written"][0]


def test_a_module_report_is_written_to_a_file_when_asked(action, tmp_path):
    open(action["data_file"], "w").close()
    output = tmp_path / "out" / "brief.md"

    assert testcoverage.run_action(module = "mod", show_source = True, output_file = str(output)) is True
    assert output.read_text() == action["written"][0]
    assert "### unused" in output.read_text()


def test_an_unknown_module_fails(action):
    open(action["data_file"], "w").close()

    assert testcoverage.run_action(module = "nothing.py") is False
    assert action["written"] == []


def test_an_unknown_action_fails(action):
    assert testcoverage.run_action("measure") is False


def test_a_missing_checkout_fails(action, monkeypatch, tmp_path):
    monkeypatch.setattr(testcoverage, "get_repo_dir", lambda: str(tmp_path / "nowhere"))

    assert testcoverage.run_action(testcoverage.ACTION_REPORT) is False


def test_run_without_coverage_installed_fails(action, monkeypatch):
    monkeypatch.setattr(testcoverage, "is_coverage_available", lambda: False)

    assert testcoverage.run_action(testcoverage.ACTION_RUN) is False
    assert action["measured"] == []


def test_a_failed_export_fails(action, monkeypatch):
    open(action["data_file"], "w").close()
    monkeypatch.setattr(testcoverage, "export_json", lambda *args, **kwargs: False)

    assert testcoverage.run_action(testcoverage.ACTION_REPORT) is False


def test_the_data_lives_in_the_cache(isolated_settings):
    data_file = testcoverage.get_data_file()

    assert data_file.startswith(testcoverage.get_data_dir())
    assert os.path.basename(testcoverage.get_data_dir()) == "Coverage"
