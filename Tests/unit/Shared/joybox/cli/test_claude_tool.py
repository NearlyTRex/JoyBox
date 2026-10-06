# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import claude_tool


###########################################################
# claude_tool
#
# A prompt file and, outside a pretend run, an API key are required before
# any file is sent; extensions are normalised to start with a dot.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    command = CommandHarness(monkeypatch, claude_tool)
    command.configured = True
    command.process = Recorder(result = (2, 1, 0))
    command.source = tmp_path / "in"
    command.source.mkdir()
    for name in ["a.txt", "b.md", "c.py"]:
        (command.source / name).write_text("")
    command.prompt = tmp_path / "prompt.txt"
    command.prompt.write_text("Summarise")
    command.output = str(tmp_path / "out")
    monkeypatch.setattr(claude_tool.claude, "is_configured", lambda: command.configured)
    monkeypatch.setattr(claude_tool.claude, "process_files", command.process)
    return command


def invoke(tool, *extra):
    return tool.main("-i", str(tool.source), "-o", tool.output, "-f", str(tool.prompt), *extra)


def test_files_are_processed_with_the_defaults(tool):
    invoke(tool, "--no-preview")

    assert tool.process.calls == [{
        "input_path": str(tool.source),
        "output_path": tool.output,
        "prompt_file": str(tool.prompt),
        "extensions": [],
        "model": claude_tool.claude.DEFAULT_MODEL,
        "max_tokens": claude_tool.claude.DEFAULT_MAX_TOKENS,
        "skip_existing": False,
        "verbose": False,
        "pretend_run": False}]
    assert tool.infos == ["Completed: 2 success, 1 skipped, 0 errors"]


def test_extensions_are_normalised_and_options_passed(tool):
    invoke(tool, "--no-preview", "-w", "txt, .md,,", "-m", "claude-test", "-t", "100", "-e")

    call = tool.process.calls[0]
    assert call["extensions"] == [".txt", ".md"]
    assert (call["model"], call["max_tokens"], call["skip_existing"]) == ("claude-test", 100, True)


def test_errors_are_summarised_as_a_warning(tool):
    tool.process.result = (1, 0, 3)

    invoke(tool, "--no-preview")

    assert tool.warnings == ["Completed: 1 success, 0 skipped, 3 errors"]


def test_the_preview_counts_every_file(tool):
    invoke(tool)

    title, details = tool.previews[0]
    assert title == "Process files with Claude"
    assert "Files: 3" in details
    assert not any(line.startswith("Extensions") for line in details)


def test_the_preview_counts_only_matching_files(tool):
    invoke(tool, "-w", "txt,md")

    details = tool.previews[0][1]
    assert "Files: 2" in details
    assert details[-1] == "Extensions: .txt, .md"


def test_a_declined_preview_sends_nothing(tool):
    tool.confirm = False

    invoke(tool)

    assert tool.process.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_prompt_file_is_required(tool):
    with pytest.raises(SystemExit):
        tool.main("-i", str(tool.source), "-o", tool.output, "--no-preview")
    assert tool.errors == ["Prompt file is required (-f/--prompt_file)"]


def test_a_missing_prompt_file_stops_the_run(tool, tmp_path):
    with pytest.raises(SystemExit):
        tool.main("-i", str(tool.source), "-o", tool.output, "-f", str(tmp_path / "missing.txt"), "--no-preview")
    assert tool.errors == ["Prompt file not found: %s" % (tmp_path / "missing.txt")]


def test_an_unconfigured_api_key_stops_a_real_run(tool):
    tool.configured = False

    with pytest.raises(SystemExit):
        invoke(tool, "--no-preview")
    assert tool.errors == ["Anthropic API key not configured"]
    assert tool.process.calls == []


def test_a_pretend_run_needs_no_api_key(tool):
    tool.configured = False

    invoke(tool, "--no-preview", "-p")

    assert tool.process.values("pretend_run") == [True]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, claude_tool)
