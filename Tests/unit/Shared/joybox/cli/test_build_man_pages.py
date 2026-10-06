# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import build_man_pages


###########################################################
# build_man_pages
#
# --check fails on incomplete help or a page that would change; otherwise the
# pages are written, or only compared on a pretend run.
###########################################################

SHARED_FOLDER = os.path.realpath(os.path.join(os.path.dirname(build_man_pages.__file__), "..", ".."))
REPO_FOLDER = os.path.dirname(SHARED_FOLDER)


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, build_man_pages)
    command.specs = {"alpha": "alpha spec", "beta": "beta spec"}
    command.problems = {}
    command.described = Recorder(result = lambda project_path, folders: command.specs)
    command.stale = Recorder(result = ([], []))
    command.written = Recorder(result = (["alpha.md"], ["gone.md"]))
    monkeypatch.setattr(build_man_pages.manpage, "describe_commands", command.described)
    monkeypatch.setattr(build_man_pages.manpage, "find_help_problems",
                        lambda name, spec, names: command.problems.get(name, []))
    monkeypatch.setattr(build_man_pages.manpage, "render_all", lambda specs: {name + ".md": spec for name, spec in specs.items()})
    monkeypatch.setattr(build_man_pages.manpage, "find_stale_pages", command.stale)
    monkeypatch.setattr(build_man_pages.manpage, "write_pages", command.written)
    return command


def test_pages_are_written_to_the_repo_docs_by_default(tool):
    assert tool.main() is True

    assert tool.described.calls == [{"_args": (os.path.join(REPO_FOLDER, "pyproject.toml"), [SHARED_FOLDER])}]
    pages, output_path = tool.written.calls[0]["_args"]
    assert pages == {"alpha.md": "alpha spec", "beta.md": "beta spec"}
    assert output_path == os.path.join(REPO_FOLDER, "Docs", "reference", "man")
    assert tool.infos == ["Updated 1 page(s), removed 1, in %s" % output_path]


def test_a_pretend_run_only_compares(tool, tmp_path):
    tool.stale.result = (["alpha.md", "beta.md"], [])

    assert tool.main("-o", str(tmp_path), "-s", "custom.toml", "-p") is True

    assert tool.described.calls[0]["_args"][0] == "custom.toml"
    assert tool.written.calls == []
    assert tool.infos == ["Updated 2 page(s), removed 0, in %s" % tmp_path]


def test_help_problems_are_reported_as_warnings(tool):
    tool.problems = {"beta": ["no examples"]}

    tool.main()

    assert tool.warnings == ["beta: no examples"]


def test_check_passes_when_everything_is_current(tool):
    assert tool.main("-k") is True

    assert tool.written.calls == []
    assert tool.warnings == []


def test_check_fails_on_stale_or_extra_pages(tool):
    tool.stale.result = (["alpha.md"], ["gone.md"])

    assert tool.main("-k") is False

    assert tool.warnings == ["Out of date: alpha.md", "No longer generated: gone.md"]


def test_check_fails_on_help_problems(tool):
    tool.problems = {"alpha": ["no description"]}

    assert tool.main("-k") is False


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, build_man_pages)
