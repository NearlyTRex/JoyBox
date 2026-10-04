# Third-party imports
import pytest

# Local imports
from joybox import llmchat
from llmchat_helpers import roles


###########################################################
# Chat sessions
#
# A conversation plus the token budget it has to fit inside. Overrunning the
# window silently truncates the context, which reads as the model ignoring the
# files it was given.
###########################################################

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


def test_a_failed_backend_reply_leaves_no_trace(session, backend, monkeypatch):
    monkeypatch.setattr(llmchat.logger, "log_error", lambda message: None)
    backend.error = llmchat.RequestFailed("model crashed")

    assert session.ask("what is this?", lambda text: None) is None
    assert session.messages == []


def test_a_broken_response_leaves_no_trace(session, backend, monkeypatch):
    import http.client
    monkeypatch.setattr(llmchat.logger, "log_error", lambda message: None)
    backend.error = http.client.IncompleteRead(b"partial")

    assert session.ask("what is this?", lambda text: None) is None
    assert session.messages == []


def test_an_outline_is_attached_without_its_body(session, tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def keeper():\n    secret_body_line = 1\n    return secret_body_line\n")
    session.attach_outline(str(target))
    content = session.messages[0]["content"]

    assert "keeper" in content
    assert "secret_body_line" not in content


###########################################################
# Coding preset
###########################################################

def test_a_named_coding_model_is_used_as_it_is(monkeypatch):
    monkeypatch.setattr(llmchat.ollama, "prepare_coding_model", lambda context_tokens: pytest.fail("prepared"))

    assert llmchat.get_coding_model("devstral:24b") == "devstral:24b"


def test_without_a_name_the_server_best_is_prepared_for_a_chat_window(monkeypatch):
    asked = []
    monkeypatch.setattr(llmchat.ollama, "prepare_coding_model",
        lambda context_tokens: asked.append(context_tokens) or "devstral-small-2:24b-ctx32k")

    assert llmchat.get_coding_model() == "devstral-small-2:24b-ctx32k"
    assert asked == [llmchat.CODING_CONTEXT_TOKENS]
