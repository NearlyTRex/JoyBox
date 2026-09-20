# Imports
import os
import pytest

# Local imports
from joybox import llmchat


###########################################################
# Chat sessions
#
# A conversation plus the token budget it has to fit inside. Overrunning the
# window silently truncates the context, which reads as the model ignoring the
# files it was given.
###########################################################

class RecordingBackend:

    def __init__(self, reply = "an answer", model_names = ("small", "large"),
                 limits = None):
        self.reply = reply
        self.model_names = list(model_names)
        self.limits = limits or {"small": 4096, "large": 32768}
        self.calls = []
        self.error = None

    def models(self):
        return self.model_names

    def context_limit(self, model):
        return self.limits.get(model, 0)

    def stream(self, model, messages, temperature, max_tokens, num_ctx, on_text):
        self.calls.append({
            "model": model,
            "messages": [dict(entry) for entry in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        })
        if self.error:
            raise self.error
        on_text(self.reply)
        return self.reply


@pytest.fixture
def backend():
    return RecordingBackend()


@pytest.fixture
def session(backend):
    return llmchat.Session(backend, "small")


def roles(session):
    return [entry["role"] for entry in session.messages]


###########################################################
# Backend selection
###########################################################

def test_every_backend_key_builds_a_backend():
    for key in llmchat.get_backend_keys():
        assert llmchat.make_backend(key) is not None


def test_the_backend_keys_are_distinct():
    keys = llmchat.get_backend_keys()

    assert len(set(keys)) == len(keys)


def test_an_unknown_backend_is_refused(monkeypatch):
    errors = []
    monkeypatch.setattr(llmchat.logger, "log_error", errors.append)

    assert llmchat.make_backend("not-a-backend") is None
    assert errors


def test_each_backend_key_builds_a_distinct_type():
    built = [type(llmchat.make_backend(key)) for key in llmchat.get_backend_keys()]

    assert len(set(built)) == len(built)


###########################################################
# Seeding
###########################################################

def test_a_new_session_holds_nothing(session):
    assert session.messages == []
    assert session.tokens() == 0


def test_system_text_becomes_a_system_message(session):
    session.seed_context(system_text = "You answer questions about this repo.")

    assert roles(session) == ["system"]
    assert "answer questions" in session.messages[0]["content"]


def test_a_system_file_is_read(session, tmp_path):
    target = tmp_path / "system.md"
    target.write_text("You are terse.\n")
    session.seed_context(system_file = str(target))

    assert "You are terse." in session.messages[0]["content"]


def test_a_system_file_and_text_are_combined(session, tmp_path):
    target = tmp_path / "system.md"
    target.write_text("From the file.\n")
    session.seed_context(system_file = str(target), system_text = "And the flag.")
    content = session.messages[0]["content"]

    assert "From the file." in content
    assert "And the flag." in content


def test_attachments_become_a_read_exchange(session, tmp_path):
    # The model is asked to acknowledge the files before the first question.
    target = tmp_path / "module.py"
    target.write_text("def one():\n    return 1\n")
    session.seed_context(attachments = [str(target)])

    assert roles(session) == ["user", "assistant"]


def test_an_attachment_carries_its_content(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def unmistakable():\n    return 1\n")
    session.seed_context(attachments = [str(target)])

    assert "unmistakable" in session.messages[0]["content"]


def test_an_outline_omits_the_body(session, tmp_path):
    # Outlining rather than attaching is what keeps a large corpus workable.
    target = tmp_path / "module.py"
    target.write_text("def keeper():\n    secret_body_line = 1\n    return secret_body_line\n")
    session.seed_context(outlines = [str(target)])
    content = session.messages[0]["content"]

    assert "keeper" in content
    assert "secret_body_line" not in content


def test_a_seed_with_no_content_is_empty(session):
    session.seed_context()

    assert session.messages == []


def test_a_system_prompt_precedes_the_attachments(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def one():\n    return 1\n")
    session.seed_context(system_text = "Be terse.", attachments = [str(target)])

    assert roles(session) == ["system", "user", "assistant"]


def test_seeding_returns_the_messages(session):
    returned = session.seed_context(system_text = "Be terse.")

    assert returned == session.messages


def test_the_seed_and_the_history_are_separate_lists(session):
    session.seed_context(system_text = "Be terse.")
    session.add_block("extra")

    assert len(session.seed) == 1
    assert len(session.messages) == 3


###########################################################
# Reset
###########################################################

def test_a_reset_keeps_the_seed(session):
    session.seed_context(system_text = "Be terse.")
    session.add_block("a question's worth of context")
    session.reset()

    assert session.messages == session.seed


def test_a_reset_drops_the_conversation(session):
    session.seed_context(system_text = "Be terse.")
    session.add_block("context")
    session.reset()

    assert len(session.messages) == 1


def test_resetting_twice_is_stable(session):
    session.seed_context(system_text = "Be terse.")
    session.reset()
    session.reset()

    assert len(session.messages) == 1


def test_a_reset_does_not_share_the_seed_list(session):
    # A later add would otherwise grow the seed itself.
    session.seed_context(system_text = "Be terse.")
    session.reset()
    session.add_block("context")

    assert len(session.seed) == 1


def test_a_session_with_no_seed_resets_to_nothing(session):
    session.add_block("context")
    session.reset()

    assert session.messages == []


###########################################################
# Budget
###########################################################

def test_an_unlimited_session_has_room_for_anything(session):
    assert session.has_room_for("x" * 100000) is True


def test_a_limited_session_refuses_an_oversized_block(backend):
    session = llmchat.Session(backend, "small", limit = 1000, max_tokens = 100)

    assert session.has_room_for("x" * 100000) is False


def test_a_limited_session_accepts_a_small_block(backend):
    session = llmchat.Session(backend, "small", limit = 100000, max_tokens = 100)

    assert session.has_room_for("a short block") is True


def test_the_reply_budget_is_reserved(backend):
    # Room for the question is not enough; the answer has to fit too.
    session = llmchat.Session(backend, "small", limit = 1000, max_tokens = 0)
    generous = session.has_room_for("x" * 2000)
    session.max_tokens = 100000

    assert generous != session.has_room_for("x" * 2000)


def test_an_unlimited_seed_never_overruns(session):
    session.seed_context(system_text = "x" * 100000)

    assert session.seed_overruns() is False


def test_an_oversized_seed_overruns(backend):
    # A truncated context reads as the model ignoring its files, so a caller
    # should refuse rather than proceed.
    session = llmchat.Session(backend, "small", limit = 1000, max_tokens = 100)
    session.seed_context(system_text = "x" * 100000)

    assert session.seed_overruns() is True


def test_a_modest_seed_does_not_overrun(backend):
    session = llmchat.Session(backend, "small", limit = 100000, max_tokens = 100)
    session.seed_context(system_text = "a short prompt")

    assert session.seed_overruns() is False


def test_the_seed_budget_ignores_later_turns(backend):
    session = llmchat.Session(backend, "small", limit = 100000, max_tokens = 100)
    session.seed_context(system_text = "short")
    before = session.seed_tokens()
    session.add_block("x" * 10000)

    assert session.seed_tokens() == before
    assert session.tokens() > before


###########################################################
# Blocks
###########################################################

def test_a_block_is_acknowledged(session):
    # The read turn is what makes the model treat it as given, not as a
    # question to answer.
    session.add_block("some content")

    assert roles(session) == ["user", "assistant"]


def test_a_fitting_block_is_offered_and_added(session):
    added, cost = session.offer_block("some content")

    assert added is True
    assert cost > 0
    assert len(session.messages) == 2


def test_an_oversized_block_is_refused_without_being_added(backend):
    session = llmchat.Session(backend, "small", limit = 1000, max_tokens = 100)
    added, cost = session.offer_block("x" * 100000)

    assert added is False
    assert cost > 0
    assert session.messages == []


def test_an_offer_reports_the_cost_even_when_refused(backend):
    # The caller tells the user how far over they are.
    session = llmchat.Session(backend, "small", limit = 10, max_tokens = 0)
    added, cost = session.offer_block("x" * 4000)

    assert added is False
    assert cost > 100


def test_a_file_is_attached(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def unmistakable():\n    return 1\n")
    session.attach_file(str(target))

    assert "unmistakable" in session.messages[0]["content"]


def test_a_slice_attaches_only_its_lines(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("".join("line%d\n" % index for index in range(1, 21)))
    session.attach_slice(str(target), 5, 7)
    content = session.messages[0]["content"]

    assert "line5" in content
    assert "line1\n" not in content
    assert "line20" not in content


def test_a_missing_region_attaches_nothing(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def one():\n    return 1\n")

    assert session.attach_region(str(target), "not_a_region") is False
    assert session.messages == []


def test_a_present_region_is_attached(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def keeper():\n    return 1\n\ndef other():\n    return 2\n")

    assert session.attach_region(str(target), "keeper") is True
    assert "keeper" in session.messages[0]["content"]


###########################################################
# Asking
###########################################################

def test_a_question_and_its_answer_are_kept(session, backend):
    reply = session.ask("what is this?", lambda text: None)

    assert reply == backend.reply
    assert roles(session) == ["user", "assistant"]
    assert session.messages[-1]["content"] == backend.reply


def test_the_answer_is_streamed(session):
    streamed = []
    session.ask("what is this?", streamed.append)

    assert streamed == ["an answer"]


def test_the_question_reaches_the_backend(session, backend):
    session.ask("what is this?", lambda text: None)

    assert backend.calls[0]["messages"][-1]["content"] == "what is this?"


def test_the_session_settings_reach_the_backend(backend):
    session = llmchat.Session(backend, "large", limit = 999, temperature = 0.7,
                              max_tokens = 128)
    session.ask("what is this?", lambda text: None)

    assert backend.calls[0]["model"] == "large"
    assert backend.calls[0]["temperature"] == 0.7
    assert backend.calls[0]["max_tokens"] == 128


def test_a_failed_request_leaves_no_trace(session, backend, monkeypatch):
    # A question kept without its answer would be re-sent with the next one.
    monkeypatch.setattr(llmchat.logger, "log_error", lambda message: None)
    backend.error = OSError("connection refused")

    assert session.ask("what is this?", lambda text: None) is None
    assert session.messages == []


def test_a_failed_request_keeps_earlier_turns(session, backend, monkeypatch):
    monkeypatch.setattr(llmchat.logger, "log_error", lambda message: None)
    session.ask("first", lambda text: None)
    backend.error = OSError("connection refused")
    session.ask("second", lambda text: None)

    assert roles(session) == ["user", "assistant"]
    assert session.messages[0]["content"] == "first"


def test_the_seed_is_sent_with_the_question(session, backend):
    session.seed_context(system_text = "Be terse.")
    session.ask("what is this?", lambda text: None)

    assert backend.calls[0]["messages"][0]["role"] == "system"


###########################################################
# Transcript
###########################################################

def test_a_transcript_names_each_role(session):
    session.ask("what is this?", lambda text: None)
    transcript = session.transcript()

    assert "## user" in transcript
    assert "## assistant" in transcript


def test_a_transcript_carries_the_content(session):
    session.ask("what is this?", lambda text: None)

    assert "what is this?" in session.transcript()


def test_an_empty_transcript_is_empty(session):
    assert session.transcript() == ""


###########################################################
# Slash commands
#
# Documented as front end agnostic, so a caller that does not pre-filter its
# input must not be able to end the session by accident.
###########################################################

class Transcript:

    def __init__(self):
        self.said = []
        self.warned = []

    def say(self, text):
        self.said.append(text)

    def warn(self, text):
        self.warned.append(text)

    def all(self):
        return "\n".join(self.said + self.warned)


@pytest.fixture
def chat(session):
    session.seed_context(system_text = "Be terse.")
    return session


@pytest.fixture
def output():
    return Transcript()


def run(line, session, output, window_override = 0):
    return llmchat.handle_command(line, session, output.say, output.warn, window_override)


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
    # Every other failure here warns and carries on; this one used to raise
    # straight out through the caller's loop.
    run("/save %s" % (tmp_path / "absent" / "transcript.md"), chat, output)

    assert output.warned


def test_saving_to_an_unwritable_path_continues_the_session(chat, output, tmp_path):
    assert run("/save %s" % (tmp_path / "absent" / "transcript.md"), chat, output) is True


def test_a_failed_save_says_nothing_succeeded(chat, output, tmp_path):
    run("/save %s" % (tmp_path / "absent" / "transcript.md"), chat, output)

    assert not any("wrote" in line for line in output.said)
