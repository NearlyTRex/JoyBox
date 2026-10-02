# Imports
import os
import sys
import types
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from joybox import claude

FAKE_API_KEY = "configured-for-tests"


###########################################################
# Configuration
#
# The key lives in JoyBox.ini; everything else depends on whether it is set.
###########################################################

@pytest.fixture
def configured_key(monkeypatch):
    state = {"value": FAKE_API_KEY, "asked": []}

    def get_value(section, field, default_value = None, throw_exception = True):
        state["asked"].append((section, field, throw_exception))
        return state["value"]
    monkeypatch.setattr(claude.settings, "get_value", get_value)
    return state


def test_the_key_is_read_from_the_anthropic_section(configured_key):
    assert claude.get_api_key() == FAKE_API_KEY
    assert configured_key["asked"] == [("UserData.Anthropic", "anthropic_api_key", False)]


@pytest.mark.parametrize("value", [None, ""])
def test_an_unset_key_is_none(configured_key, value):
    configured_key["value"] = value

    assert claude.get_api_key() is None
    assert claude.is_configured() is False


def test_a_set_key_is_configured(configured_key):
    assert claude.is_configured() is True


###########################################################
# Client
###########################################################

class FakeMessages:
    def __init__(self, owner):
        self.owner = owner

    def create(self, **params):
        self.owner.requests.append(params)
        if self.owner.error:
            raise self.owner.error
        return self.owner.response


class FakeAnthropic:
    instances: ClassVar[list] = []

    def __init__(self, api_key):
        self.api_key = api_key
        self.requests = []
        self.error = None
        self.response = types.SimpleNamespace(content = [types.SimpleNamespace(text = "reply")])
        self.messages = FakeMessages(self)
        FakeAnthropic.instances.append(self)


@pytest.fixture
def library(monkeypatch, configured_key):
    FakeAnthropic.instances = []
    monkeypatch.setitem(
        sys.modules, "anthropic", types.SimpleNamespace(Anthropic = FakeAnthropic))
    return FakeAnthropic


def test_a_client_is_built_with_the_configured_key(library):
    client = claude.create_client()

    assert isinstance(client, FakeAnthropic)
    assert client.api_key == FAKE_API_KEY


def test_no_client_without_the_library(monkeypatch, configured_key):
    monkeypatch.setitem(sys.modules, "anthropic", None)

    assert claude.create_client() is None


def test_no_client_without_a_key(library, configured_key):
    configured_key["value"] = None

    assert claude.create_client() is None
    assert library.instances == []


###########################################################
# Sending a message
###########################################################

@pytest.fixture
def client(monkeypatch):
    instance = FakeAnthropic(FAKE_API_KEY)
    monkeypatch.setattr(claude, "create_client", lambda: instance)
    return instance


def test_a_message_uses_the_defaults(client):
    assert claude.send_message("hello") == "reply"
    assert client.requests == [{
        "model": claude.DEFAULT_MODEL,
        "max_tokens": claude.DEFAULT_MAX_TOKENS,
        "messages": [{"role": "user", "content": "hello"}],
    }]


def test_a_message_carries_its_options(client):
    claude.send_message(
        "hello", model = "other", max_tokens = 10, system_prompt = "be brief", verbose = True)

    assert client.requests[0]["model"] == "other"
    assert client.requests[0]["max_tokens"] == 10
    assert client.requests[0]["system"] == "be brief"


def test_nothing_is_sent_without_a_client(monkeypatch):
    monkeypatch.setattr(claude, "create_client", lambda: None)

    assert claude.send_message("hello") is None


def test_an_empty_reply_is_none(client):
    client.response = types.SimpleNamespace(content = [])

    assert claude.send_message("hello") is None


@pytest.mark.parametrize("error, expected", [
    ("Your credit balance is too low", "Insufficient credits"),
    ("invalid_api_key", "Invalid API key"),
    ("Authentication failed", "Invalid API key"),
    ("rate_limit_error", "Rate limited"),
    ("Overloaded", "Service overloaded"),
    ("boom", "Anthropic API error: boom"),
])
def test_an_api_error_becomes_a_warning(client, monkeypatch, error, expected):
    warnings = []
    monkeypatch.setattr(claude.logger, "log_warning", lambda message: warnings.append(message))
    client.error = RuntimeError(error)

    assert claude.send_message("hello") is None
    assert len(warnings) == 1
    assert expected in warnings[0]


###########################################################
# Processing one file
###########################################################

@pytest.fixture
def sent(monkeypatch):
    messages = []

    def send_message(**kwargs):
        messages.append(kwargs)
        return "result"
    monkeypatch.setattr(claude, "send_message", send_message)
    return messages


def test_the_template_is_filled_from_the_file(tmp_path, sent):
    source = tmp_path / "notes.txt"
    source.write_text("body")
    template = "{file_content}|{filename}|{file_basename}|{file_extension}|{input_file}|{input_dir}|{output_dir}"

    assert claude.process_file(
        str(source), template, input_dir = "in", output_dir = "out", model = "m") == "result"
    assert sent[0]["prompt"] == "body|notes.txt|notes|.txt|%s|in|out" % source
    assert sent[0]["model"] == "m"


def test_directories_are_left_unfilled_when_not_given(tmp_path, sent):
    source = tmp_path / "notes.txt"
    source.write_text("body")

    claude.process_file(str(source), "{input_dir}{output_dir}")

    assert sent[0]["prompt"] == "{input_dir}{output_dir}"


def test_an_unreadable_file_is_not_sent(tmp_path, sent):
    assert claude.process_file(str(tmp_path / "absent.txt"), "{file_content}") is None
    assert sent == []


###########################################################
# Processing a tree
###########################################################

@pytest.fixture
def tree(tmp_path, monkeypatch):
    source = tmp_path / "in"
    (source / "sub").mkdir(parents = True)
    (source / "a.txt").write_text("alpha")
    (source / "sub" / "b.md").write_text("beta")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Rewrite {file_content}")
    state = {
        "source": str(source),
        "output": str(tmp_path / "out"),
        "prompt": str(prompt),
        "results": {},
        "seen": [],
    }

    def process_file(input_file, prompt_template, **kwargs):
        state["seen"].append(os.path.relpath(input_file, state["source"]))
        return state["results"].get(os.path.basename(input_file), "done")
    monkeypatch.setattr(claude, "process_file", process_file)
    return state


def run(tree, **kwargs):
    return claude.process_files(tree["source"], tree["output"], tree["prompt"], **kwargs)


def test_every_file_is_written_beside_its_relative_path(tree):
    assert run(tree, verbose = True) == (2, 0, 0)
    assert open(os.path.join(tree["output"], "a.txt")).read() == "done"
    assert open(os.path.join(tree["output"], "sub", "b.md")).read() == "done"


def test_extensions_narrow_the_file_list(tree):
    assert run(tree, extensions = [".md"]) == (1, 0, 0)
    assert tree["seen"] == [os.path.join("sub", "b.md")]


def test_an_existing_output_is_skipped_when_asked(tree):
    os.makedirs(tree["output"])
    with open(os.path.join(tree["output"], "a.txt"), "w") as handle:
        handle.write("kept")

    assert run(tree, skip_existing = True, verbose = True) == (1, 1, 0)
    assert open(os.path.join(tree["output"], "a.txt")).read() == "kept"


def test_an_existing_output_is_skipped_quietly(tree):
    os.makedirs(tree["output"])
    with open(os.path.join(tree["output"], "a.txt"), "w") as handle:
        handle.write("kept")

    assert run(tree, skip_existing = True) == (1, 1, 0)


def test_a_pretend_run_writes_nothing(tree):
    assert run(tree, pretend_run = True) == (2, 0, 0)
    assert tree["seen"] == []
    assert not os.path.exists(tree["output"])


def test_a_failed_file_is_counted_as_an_error(tree):
    tree["results"]["a.txt"] = None

    assert run(tree) == (1, 0, 1)
    assert not os.path.exists(os.path.join(tree["output"], "a.txt"))


def test_a_failed_write_is_counted_as_an_error(tree, monkeypatch):
    monkeypatch.setattr(claude.serialization, "write_text_file", lambda **kwargs: False)

    assert run(tree) == (0, 0, 2)


def test_an_unreadable_prompt_processes_nothing(tree):
    tree["prompt"] = tree["prompt"] + ".missing"

    assert run(tree) == (0, 0, 0)
    assert tree["seen"] == []


def test_an_empty_tree_processes_nothing(tree, tmp_path):
    tree["source"] = str(tmp_path / "empty")
    os.makedirs(tree["source"])

    assert run(tree) == (0, 0, 0)
