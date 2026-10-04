# Imports
import pytest

# Local imports
from joybox import llmchat
from llmchat_helpers import run


###########################################################
# Slash commands
#
# Documented as front end agnostic, so a caller that does not pre-filter its
# input must not be able to end the session by accident.
###########################################################

@pytest.mark.parametrize("line", ["/quit", "/exit", "/q"])
def test_a_quit_command_ends_the_session(chat, output, line):
    assert run(line, chat, output) is False


def test_every_other_command_continues_the_session(chat, output):
    for line in ["/help", "/tokens", "/reset", "/model", "/not-a-command"]:
        assert run(line, chat, output) is True


@pytest.mark.parametrize("line", ["", "   ", "\t", "\n"])
def test_a_blank_line_is_not_a_command(chat, output, line):
    # A front end that does not filter blank input should not crash.
    assert run(line, chat, output) is True
    assert output.all() == ""


def test_an_unknown_command_is_reported(chat, output):
    run("/not-a-command", chat, output)

    assert output.warned and "/not-a-command" in output.warned[0]


def test_help_lists_the_commands(chat, output):
    run("/help", chat, output)

    assert "/attach" in output.all()
    assert "/quit" in output.all()


###########################################################
# Models
###########################################################

def test_listing_models_shows_them_all(chat, output):
    run("/model", chat, output)

    assert "small" in output.all()
    assert "large" in output.all()


def test_the_current_model_is_marked(chat, output):
    run("/model", chat, output)
    current = [line for line in output.said if "small" in line][0]

    assert "*" in current


def test_switching_models_takes_effect(chat, output):
    run("/model large", chat, output)

    assert chat.model == "large"


def test_switching_models_adopts_its_window(chat, output, backend):
    # A window left at the old model's size would truncate or waste context.
    run("/model large", chat, output)

    assert chat.limit == backend.limits["large"]


def test_an_explicit_window_overrides_the_backend(chat, output):
    run("/model large", chat, output, window_override = 1234)

    assert chat.limit == 1234


def test_switching_to_an_unknown_model_leaves_no_window(chat, output):
    run("/model unknown", chat, output)

    assert chat.model == "unknown"
    assert chat.limit == 0


###########################################################
# Attaching
###########################################################

@pytest.fixture
def module_file(tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def unmistakable():\n    return 1\n\ndef other():\n    return 2\n")
    return target


def test_attaching_adds_the_file(chat, output, module_file):
    before = len(chat.messages)
    run("/attach %s" % module_file, chat, output)

    assert len(chat.messages) > before
    assert "unmistakable" in chat.messages[-2]["content"]


def test_attaching_reports_the_cost(chat, output, module_file):
    run("/attach %s" % module_file, chat, output)

    assert "tokens" in output.all()


def test_attaching_a_missing_file_is_reported(chat, output, tmp_path):
    before = len(chat.messages)
    run("/attach %s" % (tmp_path / "absent.py"), chat, output)

    assert output.warned
    assert len(chat.messages) == before


def test_attaching_a_directory_is_reported(chat, output, tmp_path):
    run("/attach %s" % tmp_path, chat, output)

    assert output.warned


def test_outlining_omits_the_body(chat, output, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def keeper():\n    secret_body_line = 1\n    return secret_body_line\n")
    run("/outline %s" % target, chat, output)
    content = chat.messages[-2]["content"]

    assert "keeper" in content
    assert "secret_body_line" not in content


def test_an_oversized_attachment_is_refused(backend, output, tmp_path):
    session = llmchat.Session(backend, "small", limit = 200, max_tokens = 100)
    target = tmp_path / "big.py"
    target.write_text("x = 1\n" * 20000)
    run("/attach %s" % target, session, output)

    assert output.warned
    assert session.messages == []


def test_a_refused_attachment_suggests_an_alternative(backend, output, tmp_path):
    session = llmchat.Session(backend, "small", limit = 200, max_tokens = 100)
    target = tmp_path / "big.py"
    target.write_text("x = 1\n" * 20000)
    run("/attach %s" % target, session, output)

    assert "/outline" in output.all() or "/read" in output.all()


###########################################################
# Reading ranges
###########################################################

@pytest.fixture
def numbered_file(tmp_path):
    target = tmp_path / "numbered.txt"
    target.write_text("".join("line%d\n" % index for index in range(1, 51)))
    return target


def test_reading_a_range_adds_those_lines(chat, output, numbered_file):
    run("/read %s 5-7" % numbered_file, chat, output)
    content = chat.messages[-2]["content"]

    assert "line5" in content
    assert "line50" not in content


def test_reading_without_a_range_adds_the_file(chat, output, numbered_file):
    run("/read %s" % numbered_file, chat, output)

    assert "line1" in chat.messages[-2]["content"]


def test_a_malformed_range_is_reported(chat, output, numbered_file):
    before = len(chat.messages)
    run("/read %s 5..7" % numbered_file, chat, output)

    assert output.warned
    assert len(chat.messages) == before


def test_a_malformed_range_continues_the_session(chat, output, numbered_file):
    assert run("/read %s 5..7" % numbered_file, chat, output) is True


def test_reading_a_missing_file_is_reported(chat, output, tmp_path):
    run("/read %s 1-5" % (tmp_path / "absent.txt"), chat, output)

    assert output.warned


def test_reading_with_no_argument_is_reported(chat, output):
    run("/read", chat, output)

    assert output.warned


def test_an_oversized_slice_is_refused(backend, output, numbered_file):
    session = llmchat.Session(backend, "small", limit = 10, max_tokens = 0)
    run("/read %s" % numbered_file, session, output)

    assert "narrower range" in output.all()
    assert session.messages == []


###########################################################
# Regions
###########################################################

def test_a_region_is_added(chat, output, module_file):
    run("/region %s unmistakable" % module_file, chat, output)

    assert "unmistakable" in chat.messages[-2]["content"]


def test_an_unknown_region_is_reported(chat, output, module_file):
    before = len(chat.messages)
    run("/region %s not_a_region" % module_file, chat, output)

    assert output.warned
    assert len(chat.messages) == before


def test_a_region_command_without_a_name_is_reported(chat, output, module_file):
    run("/region %s" % module_file, chat, output)

    assert output.warned and "usage" in output.warned[0]


def test_listing_regions_names_them(chat, output, module_file):
    run("/regions %s" % module_file, chat, output)

    assert "unmistakable" in output.all()
    assert "other" in output.all()


def test_listing_regions_of_a_missing_file_is_reported(chat, output, tmp_path):
    run("/regions %s" % (tmp_path / "absent.py"), chat, output)

    assert output.warned


def test_an_oversized_region_is_refused(backend, output, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def keeper():\n" + "    x = 1\n" * 2000)
    session = llmchat.Session(backend, "small", limit = 200, max_tokens = 100)
    run("/region %s keeper" % target, session, output)

    assert "will not fit" in output.all()
    assert session.messages == []



###########################################################
# Session commands
###########################################################

def test_resetting_keeps_the_seed(chat, output):
    chat.add_block("context")
    run("/reset", chat, output)

    assert chat.messages == chat.seed


def test_tokens_reports_the_message_count(chat, output):
    run("/tokens", chat, output)

    assert "messages" in output.all()


def test_tokens_reports_the_window_when_there_is_one(backend, output):
    session = llmchat.Session(backend, "small", limit = 4096)
    run("/tokens", session, output)

    assert "4,096" in output.all()


def test_saving_writes_the_transcript(chat, output, tmp_path):
    target = tmp_path / "transcript.md"
    run("/save %s" % target, chat, output)

    assert target.exists()
    assert "## system" in target.read_text()


def test_saving_reports_where_it_went(chat, output, tmp_path):
    target = tmp_path / "transcript.md"
    run("/save %s" % target, chat, output)

    assert str(target) in output.all()


def test_saving_defaults_to_a_named_file(chat, output, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run("/save", chat, output)

    assert (tmp_path / "transcript.md").exists()


def test_saving_to_an_unwritable_path_is_reported(chat, output, tmp_path):
    # Every other failure here warns and carries on.
    run("/save %s" % (tmp_path / "absent" / "transcript.md"), chat, output)

    assert output.warned


def test_saving_to_an_unwritable_path_continues_the_session(chat, output, tmp_path):
    assert run("/save %s" % (tmp_path / "absent" / "transcript.md"), chat, output) is True


def test_a_failed_save_says_nothing_succeeded(chat, output, tmp_path):
    run("/save %s" % (tmp_path / "absent" / "transcript.md"), chat, output)

    assert not any("wrote" in line for line in output.said)
