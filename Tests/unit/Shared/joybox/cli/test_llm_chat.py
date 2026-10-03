# Imports
import io
import sys

# Third-party imports
import pytest

# Local imports
from joybox import llmchat
from joybox.cli import llm_chat


###########################################################
# llm_chat
#
# Everything that can be checked locally is checked before the first
# request, and a one-shot question that gets no answer is a failed run.
###########################################################

class FakeBackend:

    def __init__(self, models = ("small", "large"), limit = 4096, reply = "an answer"):
        self.model_names = list(models)
        self.limit = limit
        self.reply = reply
        self.questions = []

    def models(self):
        return self.model_names

    def context_limit(self, model):
        return self.limit

    def stream(self, model, messages, temperature, max_tokens, num_ctx, on_text):
        self.questions.append((model, messages[-1]["content"], temperature))
        if self.reply is None:
            raise llmchat.RequestFailed("model crashed")
        on_text(self.reply)
        return self.reply


class FakeStdin(io.StringIO):

    def __init__(self, text = "", tty = False):
        super().__init__(text)
        self.tty = tty

    def isatty(self):
        return self.tty


@pytest.fixture
def tool(monkeypatch):
    state = {"backend": FakeBackend(), "errors": [], "made": [], "lines": [],
             "commands": []}
    monkeypatch.setattr(llm_chat.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(llm_chat.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(llm_chat.logger, "log_error", state["errors"].append)
    monkeypatch.setattr(llmchat.logger, "log_error", state["errors"].append)
    monkeypatch.setattr(sys, "stdin", FakeStdin(tty = True))

    def make_backend(kind, endpoint, api_key, model):
        state["made"].append((kind, endpoint, api_key, model))
        return state["backend"]

    monkeypatch.setattr(llm_chat.llmchat, "make_backend", make_backend)

    def read_line(prompt_text):
        return state["lines"].pop(0) if state["lines"] else None

    monkeypatch.setattr(llm_chat.terminal, "read_line", read_line)
    real_handle = llmchat.handle_command

    def handle_command(line, session, say, warn, window_override = 0):
        state["commands"].append((line, window_override))
        return real_handle(line, session, say, warn, window_override)

    monkeypatch.setattr(llm_chat.llmchat, "handle_command", handle_command)

    def run(*argv, stdin = None):
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", stdin)
        monkeypatch.setattr(sys, "argv", ["llm_chat", *argv])
        return llm_chat.main()

    state["run"] = run
    return state


@pytest.fixture
def source(tmp_path):
    target = tmp_path / "module.py"
    target.write_text("def keeper():\n    return 1\n")
    return str(target)


###########################################################
# Before connecting
###########################################################

def test_listing_chunkers_prints_them_and_connects_to_nothing(tool, capsys):
    assert tool["run"]("--list_chunkers") is True
    assert ".py" in capsys.readouterr().out
    assert tool["made"] == []


def test_a_malformed_temperature_is_refused_before_connecting(tool):
    assert tool["run"]("-t", "warm", "--ask", "hi") is False
    assert "warm" in tool["errors"][0]
    assert tool["made"] == []


@pytest.mark.parametrize("flag", ["-a", "-o", "--system_file"])
def test_a_missing_file_is_refused_before_connecting(tool, tmp_path, flag):
    absent = str(tmp_path / "absent.txt")

    assert tool["run"](flag, absent, "--ask", "hi") is False
    assert absent in tool["errors"][0]
    assert tool["made"] == []


###########################################################
# Connecting
###########################################################

def test_an_unknown_backend_fails(tool, monkeypatch):
    monkeypatch.setattr(llm_chat.llmchat, "make_backend", lambda *args: None)

    assert tool["run"]("-b", "nope", "--ask", "hi") is False


def test_the_backend_settings_are_passed_through(tool):
    tool["run"]("-b", "openai", "-e", "http://host", "--api_key", "tok", "-m", "small",
                "--ask", "hi")

    assert tool["made"] == [("openai", "http://host", "tok", "small")]


def test_a_backend_with_no_models_fails(tool):
    tool["backend"].model_names = []

    assert tool["run"]("--ask", "hi") is False
    assert "No models" in tool["errors"][0]


def test_an_unlisted_model_fails(tool):
    assert tool["run"]("-m", "huge", "--ask", "hi") is False
    assert "huge" in tool["errors"][0]


def test_claude_accepts_an_unlisted_model(tool):
    assert tool["run"]("-b", llmchat.BACKEND_CLAUDE, "-m", "claude-x", "--ask", "hi") is True
    assert tool["backend"].questions[0][0] == "claude-x"


def test_the_first_listed_model_is_the_default(tool):
    tool["run"]("--ask", "hi")

    assert tool["backend"].questions[0][0] == "small"


def test_the_temperature_reaches_the_backend(tool):
    tool["run"]("-t", "0.7", "--ask", "hi")

    assert tool["backend"].questions[0][2] == 0.7


###########################################################
# Window
###########################################################

def test_a_seed_that_overruns_the_model_window_is_refused(tool, tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x" * 40000)
    tool["backend"].limit = 1000

    assert tool["run"]("-a", str(big), "--ask", "hi") is False
    assert tool["backend"].questions == []
    assert "1,000" in tool["errors"][0]


def test_an_explicit_window_overrides_the_model(tool, source):
    # The model's own window would refuse this seed.
    tool["backend"].limit = 10

    assert tool["run"]("-a", source, "--num_ctx", "100000", "--ask", "hi") is True


def test_a_seed_is_sent_with_the_question(tool, source):
    tool["run"]("--system", "Be terse.", "-o", source, "--ask", "hi")

    assert tool["backend"].questions[0][1] == "hi"


###########################################################
# One-shot
###########################################################

def test_an_answered_question_succeeds(tool, capsys):
    assert tool["run"]("--ask", "what is this?") is True
    out = capsys.readouterr().out
    assert "small" in out
    assert "an answer" in out


def test_an_unanswered_question_fails(tool):
    # A script asking one question must see the failure in the exit status.
    tool["backend"].reply = None

    assert tool["run"]("--ask", "what is this?") is False


def test_a_piped_question_is_answered(tool):
    assert tool["run"](stdin = FakeStdin("  piped question \n")) is True
    assert tool["backend"].questions[0][1] == "piped question"


def test_an_unanswered_piped_question_fails(tool):
    tool["backend"].reply = None

    assert tool["run"](stdin = FakeStdin("piped question")) is False


def test_an_empty_pipe_asks_nothing(tool):
    assert tool["run"](stdin = FakeStdin("  \n")) is True
    assert tool["backend"].questions == []


###########################################################
# Interactive
###########################################################

def test_interactive_questions_are_answered_until_end_of_input(tool):
    tool["lines"] = ["first", "   ", "second"]

    assert tool["run"]() is True
    assert [question[1] for question in tool["backend"].questions] == ["first", "second"]


def test_a_failed_interactive_question_does_not_end_the_chat(tool):
    tool["backend"].reply = None
    tool["lines"] = ["first", "second"]

    assert tool["run"]() is True
    assert len(tool["backend"].questions) == 2


def test_commands_are_handled_and_quit_ends_the_chat(tool):
    tool["lines"] = ["/tokens", "/quit", "never asked"]

    assert tool["run"]("--num_ctx", "8192") is True
    assert tool["commands"] == [("/tokens", 8192), ("/quit", 8192)]
    assert tool["backend"].questions == []


def test_the_banner_names_the_model_window_and_seed(tool, capsys):
    tool["run"]("--system", "Be terse.")
    out = capsys.readouterr().out

    assert "small via ollama, window 4,096 tokens" in out
    assert "seeded with" in out


def test_the_banner_omits_an_unknown_window_and_empty_seed(tool, capsys):
    tool["backend"].limit = 0
    tool["run"]()
    out = capsys.readouterr().out

    assert "small via ollama\n" in out
    assert "seeded" not in out


###########################################################
# Entry
###########################################################

def test_running_as_a_script_goes_through_the_shared_handling(tool, monkeypatch, capsys):
    import runpy
    logged = []
    monkeypatch.setattr(llm_chat.system.logger, "log_info", logged.append)
    monkeypatch.setattr(sys, "argv", ["llm_chat", "--list_chunkers"])

    runpy.run_path(llm_chat.__file__, run_name = "__main__")

    assert ".py" in capsys.readouterr().out
    assert logged == ["Script completed successfully"]


def test_a_failed_run_exits_with_an_error(tool, monkeypatch):
    monkeypatch.setattr(llm_chat.system.logger, "log_error", lambda message: None)
    monkeypatch.setattr(sys, "argv", ["llm_chat", "-t", "warm"])

    with pytest.raises(SystemExit) as raised:
        llm_chat.run()
    assert raised.value.code == 1
