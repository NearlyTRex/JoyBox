# Imports
import json
import urllib.error

# Third-party imports
import pytest

# Local imports
from joybox import llmchat


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
# HTTP backends
#
# Ollama and OpenAI-compatible servers are reached through urlopen, faked
# here with canned bodies and streamed lines.
###########################################################

class FakeResponse:

    def __init__(self, body = b"", lines = ()):
        self.body = body
        self.lines = list(lines)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body

    def __iter__(self):
        return iter(self.lines)


@pytest.fixture
def server(monkeypatch):
    state = {"requests": [], "response": FakeResponse(), "error": None}

    def urlopen(request, timeout = None):
        state["requests"].append(request)
        if state["error"]:
            raise state["error"]
        return state["response"]

    monkeypatch.setattr(llmchat.urllib.request, "urlopen", urlopen)
    return state


def reply(body = b"", lines = ()):
    return FakeResponse(body, [line.encode() + b"\n" for line in lines])


def sent(request):
    return json.loads(request.data.decode())


def stream(backend, on_text = None, model = "m", num_ctx = 0):
    pieces = []
    text = backend.stream(model, [{"role": "user", "content": "hi"}], 0.5, 64, num_ctx,
                          on_text or pieces.append)
    return text, pieces


def test_ollama_defaults_to_the_configured_endpoint(monkeypatch):
    monkeypatch.setattr(llmchat.ollama, "get_api_base", lambda: "http://ollama:11434")

    assert llmchat.OllamaBackend().endpoint == "http://ollama:11434"


def test_ollama_lists_its_models(server):
    server["response"] = reply(json.dumps({"data": [{"id": "a"}, {"id": "b"}]}).encode())

    assert llmchat.OllamaBackend("http://host").models() == ["a", "b"]
    assert server["requests"][0] == "http://host/v1/models"


@pytest.mark.parametrize("error", [urllib.error.URLError("down"), OSError("reset")])
def test_ollama_lists_nothing_when_unreachable(server, error):
    server["error"] = error

    assert llmchat.OllamaBackend("http://host").models() == []


def test_ollama_lists_nothing_for_a_garbled_listing(server):
    server["response"] = reply(b"not json")

    assert llmchat.OllamaBackend("http://host").models() == []


def test_ollama_reads_the_context_length(server):
    server["response"] = reply(json.dumps(
        {"model_info": {"general.name": "x", "qwen2.context_length": "32768"}}).encode())
    backend = llmchat.OllamaBackend("http://host")

    assert backend.context_limit("qwen") == 32768
    assert server["requests"][0].full_url == "http://host/api/show"
    assert sent(server["requests"][0]) == {"name": "qwen"}


@pytest.mark.parametrize("info", [{}, {"model_info": None}, {"model_info": {"general.name": "x"}},
                                  {"model_info": {"llama.context_length": None}},
                                  {"model_info": {"llama.context_length": "big"}}])
def test_ollama_reports_no_limit_without_a_usable_length(server, info):
    server["response"] = reply(json.dumps(info).encode())

    assert llmchat.OllamaBackend("http://host").context_limit("m") == 0


def test_ollama_reports_no_limit_when_unreachable(server):
    server["error"] = urllib.error.URLError("down")

    assert llmchat.OllamaBackend("http://host").context_limit("m") == 0


def test_ollama_streams_the_reply(server):
    server["response"] = reply(lines = [
        json.dumps({"message": {"content": "Hel"}}),
        "",
        "not json",
        json.dumps({"message": {"content": ""}}),
        json.dumps({"message": None}),
        json.dumps({"message": {"content": "lo"}, "done": True}),
        json.dumps({"message": {"content": "after done"}}),
    ])
    text, pieces = stream(llmchat.OllamaBackend("http://host"))

    assert text == "Hello"
    assert pieces == ["Hel", "lo"]


def test_ollama_keeps_what_arrived_before_the_stream_closed(server):
    server["response"] = reply(lines = [json.dumps({"message": {"content": "partial"}})])

    assert stream(llmchat.OllamaBackend("http://host"))[0] == "partial"


def test_ollama_sends_the_window_when_given(server):
    server["response"] = reply(lines = [json.dumps({"done": True})])
    stream(llmchat.OllamaBackend("http://host"), num_ctx = 8192)
    body = sent(server["requests"][0])

    assert server["requests"][0].full_url == "http://host/api/chat"
    assert body["options"] == {"temperature": 0.5, "num_predict": 64, "num_ctx": 8192}
    assert body["stream"] is True


def test_ollama_leaves_the_window_to_the_server_otherwise(server):
    server["response"] = reply(lines = [json.dumps({"done": True})])
    stream(llmchat.OllamaBackend("http://host"))

    assert "num_ctx" not in sent(server["requests"][0])["options"]


def test_ollama_raises_a_streamed_error(server):
    # Swallowing it would record an empty answer as if the model had replied.
    server["response"] = reply(lines = [json.dumps({"error": "model crashed"})])

    with pytest.raises(llmchat.RequestFailed, match = "model crashed"):
        stream(llmchat.OllamaBackend("http://host"))


def test_openai_strips_a_trailing_slash():
    assert llmchat.OpenAIBackend("http://host/").endpoint == "http://host"


def test_openai_sends_a_key_only_when_given():
    assert "Authorization" not in llmchat.OpenAIBackend("http://host").headers()
    assert llmchat.OpenAIBackend("http://host", "tok").headers()["Authorization"] == "Bearer tok"


def test_openai_lists_its_models(server):
    server["response"] = reply(json.dumps({"data": [{"id": "a"}]}).encode())

    assert llmchat.OpenAIBackend("http://host", "tok").models() == ["a"]
    assert server["requests"][0].full_url == "http://host/v1/models"
    assert server["requests"][0].get_header("Authorization") == "Bearer tok"


def test_openai_lists_nothing_when_unreachable(server):
    server["error"] = urllib.error.URLError("down")

    assert llmchat.OpenAIBackend("http://host").models() == []


def test_openai_reports_no_limit():
    assert llmchat.OpenAIBackend("http://host").context_limit("m") == 0


def test_openai_streams_the_reply(server):
    server["response"] = reply(lines = [
        ": keep-alive",
        "data: " + json.dumps({"choices": [{"delta": {"role": "assistant"}}]}),
        "data: " + json.dumps({"choices": [{"delta": {"content": "Hel"}}]}),
        "data: not json",
        "data: " + json.dumps({"choices": []}),
        "data: " + json.dumps({"usage": {}}),
        "data: " + json.dumps({"choices": [{"delta": None}]}),
        "data: " + json.dumps({"choices": [{"delta": {"content": "lo"}}]}),
        "data: [DONE]",
        "data: " + json.dumps({"choices": [{"delta": {"content": "after done"}}]}),
    ])
    text, pieces = stream(llmchat.OpenAIBackend("http://host"))

    assert text == "Hello"
    assert pieces == ["Hel", "lo"]


def test_openai_keeps_what_arrived_before_the_stream_closed(server):
    server["response"] = reply(lines = ["data: " + json.dumps({"choices": [{"delta": {"content": "partial"}}]})])

    assert stream(llmchat.OpenAIBackend("http://host"))[0] == "partial"


def test_openai_sends_the_settings(server):
    server["response"] = reply(lines = ["data: [DONE]"])
    stream(llmchat.OpenAIBackend("http://host"))
    body = sent(server["requests"][0])

    assert server["requests"][0].full_url == "http://host/v1/chat/completions"
    assert body["temperature"] == 0.5
    assert body["max_tokens"] == 64
    assert body["stream"] is True


def test_openai_raises_a_streamed_error(server):
    server["response"] = reply(lines = ["data: " + json.dumps({"error": {"message": "overloaded"}})])

    with pytest.raises(llmchat.RequestFailed, match = "overloaded"):
        stream(llmchat.OpenAIBackend("http://host"))


def test_openai_defaults_to_a_local_server():
    assert llmchat.make_backend(llmchat.BACKEND_OPENAI).endpoint == "http://localhost:8080"


###########################################################
# Claude backend
#
# One-shot rather than streamed, so the conversation is flattened into a
# single prompt plus a system prompt.
###########################################################

@pytest.fixture
def claude(monkeypatch):
    import joybox.claude as claude_module
    state = {"calls": [], "reply": "whole reply"}

    def send_message(**kwargs):
        state["calls"].append(kwargs)
        return state["reply"]

    monkeypatch.setattr(claude_module, "send_message", send_message)
    state["module"] = claude_module
    return state


def test_claude_defaults_to_the_wrapper_model(claude):
    backend = llmchat.ClaudeBackend()

    assert backend.models() == [claude["module"].DEFAULT_MODEL]
    assert backend.context_limit("m") == 0


def test_claude_offers_the_chosen_model(claude):
    assert llmchat.ClaudeBackend("claude-x").models() == ["claude-x"]


def test_claude_flattens_the_conversation(claude):
    system, prompt = llmchat.ClaudeBackend().flatten([
        {"role": "system", "content": "Be terse."},
        {"role": "user", "content": "Q1"},
        {"role": "assistant", "content": "A1"},
        {"role": "system", "content": "Also kind."},
        {"role": "user", "content": "Q2"},
    ])

    assert system == "Be terse.\n\nAlso kind."
    assert prompt == "Human: Q1\n\nAssistant: A1\n\nHuman: Q2\n\nAssistant:"


def test_claude_returns_the_whole_reply(claude):
    text, pieces = stream(llmchat.ClaudeBackend("claude-x"), model = None)

    assert text == "whole reply"
    assert pieces == ["whole reply"]
    assert claude["calls"][0]["model"] == "claude-x"
    assert claude["calls"][0]["max_tokens"] == 64
    assert claude["calls"][0]["system_prompt"] is None


def test_claude_uses_the_session_model(claude):
    stream(llmchat.ClaudeBackend("claude-x"), model = "claude-y")

    assert claude["calls"][0]["model"] == "claude-y"


def test_claude_passes_the_system_prompt(claude):
    llmchat.ClaudeBackend().stream("m", [{"role": "system", "content": "Be terse."},
                                         {"role": "user", "content": "hi"}],
                                   0.5, 64, 0, lambda text: None)

    assert claude["calls"][0]["system_prompt"] == "Be terse."


def test_claude_raises_when_no_reply_came(claude):
    # The wrapper logs and returns None; recording "" would keep the question.
    claude["reply"] = None
    pieces = []

    with pytest.raises(llmchat.RequestFailed):
        llmchat.ClaudeBackend().stream("m", [{"role": "user", "content": "hi"}],
                                       0.5, 64, 0, pieces.append)
    assert pieces == []


def test_a_failed_claude_reply_leaves_no_trace(claude, monkeypatch):
    monkeypatch.setattr(llmchat.logger, "log_error", lambda message: None)
    claude["reply"] = None
    session = llmchat.Session(llmchat.ClaudeBackend(), "m")

    assert session.ask("hi", lambda text: None) is None
    assert session.messages == []
