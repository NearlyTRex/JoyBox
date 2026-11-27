# Imports
import http.client
import json
import os
import sys
import urllib.error
import urllib.request

# Local imports
from joybox import chunkers
from joybox import dispatch
from joybox import logger
from joybox import ollama
from joybox import ollamaagents
from joybox import serialization
from joybox import claude
from joybox import terminal

###########################################################
# Backends
###########################################################

# A backend turns a message list into streamed text. Adding one means
# implementing stream() and listing what models it offers, so the session
# and the calling script stay backend-agnostic.

BACKEND_OLLAMA = "ollama"
BACKEND_OPENAI = "openai"
BACKEND_CLAUDE = "claude"

# A backend answered, but with an error instead of a reply
class RequestFailed(Exception):
    pass

# Ollama, through its native chat route, which takes num_ctx; the OpenAI-compatible
# one keeps the small default window and silently truncates, so the model seems to
# ignore your files
class OllamaBackend:
    kind = BACKEND_OLLAMA

    def __init__(self, endpoint = None):
        self.endpoint = endpoint or ollama.get_api_base()

    # Model ids the Ollama server lists on its OpenAI-compatible route; empty when unreachable
    def models(self):
        try:
            with urllib.request.urlopen(f"{self.endpoint}/v1/models", timeout = 10) as response:
                payload = serialization.parse_json_or_none(response.read().decode()) or {}
            return [entry["id"] for entry in payload.get("data", [])]
        except (OSError, KeyError):
            return []

    # Context length the Ollama server reports for the model via /api/show; 0 when unknown
    def context_limit(self, model):
        try:
            request = urllib.request.Request(
                f"{self.endpoint}/api/show",
                data = json.dumps({"name": model}).encode(),
                headers = {"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout = 10) as response:
                info = serialization.parse_json_or_none(response.read().decode()) or {}
            for key, value in (info.get("model_info") or {}).items():
                if key.endswith(".context_length"):
                    return int(value)
        except (OSError, ValueError, TypeError, KeyError):
            return 0
        return 0

    # Stream a chat reply from /api/chat, passing each piece to on_text, with num_ctx widening the window; returns the full reply
    def stream(self, model, messages, temperature, max_tokens, num_ctx, on_text):
        options = {"temperature": temperature, "num_predict": max_tokens}
        if num_ctx:
            options["num_ctx"] = num_ctx
        request = urllib.request.Request(
            f"{self.endpoint}/api/chat",
            data = json.dumps({"model": model, "messages": messages,
                               "stream": True, "options": options}).encode(),
            headers = {"Content-Type": "application/json"})
        parts = []
        with urllib.request.urlopen(request, timeout = 900) as response:
            for raw in response:
                line = raw.decode().strip()
                if not line:
                    continue
                body = serialization.parse_json_or_none(line)
                if not isinstance(body, dict):
                    continue
                if body.get("error"):
                    raise RequestFailed(body["error"])
                piece = (body.get("message") or {}).get("content")
                if piece:
                    parts.append(piece)
                    on_text(piece)
                if body.get("done"):
                    break
        return "".join(parts)

# Any OpenAI-compatible endpoint, including llama.cpp's server
class OpenAIBackend:
    kind = BACKEND_OPENAI

    def __init__(self, endpoint, api_key = ""):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key

    # JSON content type plus a bearer token when an API key is set
    def headers(self):
        out = {"Content-Type": "application/json"}
        if self.api_key:
            out["Authorization"] = f"Bearer {self.api_key}"
        return out

    # Model ids the endpoint lists at /v1/models; empty when unreachable
    def models(self):
        try:
            request = urllib.request.Request(f"{self.endpoint}/v1/models", headers = self.headers())
            with urllib.request.urlopen(request, timeout = 10) as response:
                payload = serialization.parse_json_or_none(response.read().decode()) or {}
            return [entry["id"] for entry in payload.get("data", [])]
        except (OSError, KeyError):
            return []

    # Always 0: the endpoint does not report a window
    def context_limit(self, model):
        del model
        return 0

    # Stream a chat completion over server-sent events, passing each piece to on_text; returns the full reply
    def stream(self, model, messages, temperature, max_tokens, on_text):
        request = urllib.request.Request(
            f"{self.endpoint}/v1/chat/completions",
            data = json.dumps({"model": model, "messages": messages,
                               "temperature": temperature, "max_tokens": max_tokens,
                               "stream": True}).encode(),
            headers = self.headers())
        parts = []
        with urllib.request.urlopen(request, timeout = 900) as response:
            for raw in response:
                line = raw.decode().strip()
                if not line.startswith("data: "):
                    continue
                body = line[6:]
                if body == "[DONE]":
                    break
                event = serialization.parse_json_or_none(body)
                if not isinstance(event, dict):
                    continue
                if event.get("error"):
                    raise RequestFailed(event["error"])
                try:
                    delta = event["choices"][0].get("delta") or {}
                except (KeyError, IndexError):
                    continue
                piece = delta.get("content")
                if piece:
                    parts.append(piece)
                    on_text(piece)
        return "".join(parts)

# Claude, through the joybox.claude wrapper, which is one-shot and takes a prompt and
# a system prompt, so the reply arrives whole and the conversation is flattened
class ClaudeBackend:
    kind = BACKEND_CLAUDE

    def __init__(self, model = None):
        self.claude = claude
        self.model = model or claude.DEFAULT_MODEL

    # Only the configured Claude model
    def models(self):
        return [self.model]

    # Always 0: no window is enforced for Claude
    def context_limit(self, model):
        del model
        return 0

    # System prompt and a Human/Assistant transcript ending in an open Assistant turn, from a message list
    def flatten(self, messages):
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        turns = []
        for message in messages:
            if message["role"] == "system":
                continue
            who = "Human" if message["role"] == "user" else "Assistant"
            turns.append(f"{who}: {message['content']}")
        return system, "\n\n".join(turns) + "\n\nAssistant:"

    # Send the flattened conversation to Claude in one call and hand the whole reply to on_text; RequestFailed when none comes back
    def stream(self, model, messages, max_tokens, on_text):
        system, prompt = self.flatten(messages)
        reply = self.claude.send_message(
            prompt = prompt,
            model = model or self.model,
            max_tokens = max_tokens,
            system_prompt = system or None)
        if reply is None:
            raise RequestFailed("no reply from Claude")
        on_text(reply)
        return reply

# Build a backend from a name
def make_backend(kind, endpoint = None, api_key = "", model = None):
    if kind == BACKEND_OLLAMA:
        return OllamaBackend(endpoint)
    if kind == BACKEND_OPENAI:
        return OpenAIBackend(endpoint or "http://localhost:8080", api_key)
    if kind == BACKEND_CLAUDE:
        return ClaudeBackend(model)
    logger.log_error(f"Unknown backend: {kind}")
    return None

# Backend names available to a caller
def get_backend_keys():
    return [BACKEND_OLLAMA, BACKEND_OPENAI, BACKEND_CLAUDE]

###########################################################
# Coding preset
###########################################################

# System prompt for the coding preset, used when none is given
CODING_SYSTEM_PROMPT = (
    "You are a careful senior software engineer pairing with the user. Answer with "
    "working code that matches the style of any files provided, and explain only what "
    "is not obvious from the code. When a request is ambiguous, say what you assumed. "
    "Prefer small, complete changes over sketches, and never invent APIs: if you are "
    "unsure something exists, say so.")

# Context window for the coding preset
# A chat holds less than an agent session, and a smaller window leaves room
# for a stronger model.
CODING_CONTEXT_TOKENS = 32768

# Choose the model for the coding preset: the one named, or the best coding
# model the Ollama server can hold, prepared as ollama_tool's code action does
def get_coding_model(model = None):
    return model or ollamaagents.prepare_coding_model(CODING_CONTEXT_TOKENS)

###########################################################
# Session
###########################################################

# A conversation: its seed, its history, and the budget it must fit inside.
class Session:
    def __init__(self, backend, model, limit = 0, temperature = 0.2, max_tokens = 2048):
        self.backend = backend
        self.model = model
        self.limit = limit
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.seed = []
        self.messages = []

    ###########################################################
    # Seeding
    ###########################################################

    # Build the opening context: a system prompt, whole files, and outlines
    # of files too large to carry. Attaching an outline rather than a file
    # is what keeps a large corpus workable.
    def seed_context(self, system_file = None, system_text = None,
                     attachments = (), outlines = ()):
        system = ""
        if system_file:
            system = chunkers.read_lines(system_file)
            system = "\n".join(system)
        if system_text:
            system = (system + "\n\n" + system_text).strip()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        blocks = [chunkers.render_file(path) for path in attachments]
        blocks += [chunkers.outline(path) for path in outlines]
        if blocks:
            messages.append({
                "role": "user",
                "content": "Here are the files under discussion. Read them and "
                           "wait for my question.\n\n" + "\n\n".join(blocks)})
            messages.append({
                "role": "assistant",
                "content": "I have read them. What would you like to know?"})
        self.seed = messages
        self.messages = list(messages)
        return messages

    # Drop everything after the seed context
    def reset(self):
        self.messages = list(self.seed)

    ###########################################################
    # Budget
    ###########################################################

    # Estimated token count of the whole conversation
    def tokens(self):
        return chunkers.estimate_tokens("".join(m["content"] for m in self.messages))

    # Estimated token count of the seed context alone
    def seed_tokens(self):
        return chunkers.estimate_tokens("".join(m["content"] for m in self.seed))

    # Whether a block of this size can still be added
    def has_room_for(self, text):
        if not self.limit:
            return True
        return self.tokens() + chunkers.estimate_tokens(text) + self.max_tokens <= self.limit

    # Whether the seed itself already overruns the window. A truncated
    # context reads as the model ignoring its files, so a caller should
    # refuse rather than proceed.
    def seed_overruns(self):
        return bool(self.limit) and self.seed_tokens() + self.max_tokens > self.limit

    ###########################################################
    # Content
    ###########################################################

    # Add a block as a read turn, so the model acknowledges it
    def add_block(self, text):
        self.messages.append({"role": "user", "content": text})
        self.messages.append({"role": "assistant", "content": "Read it."})

    # Add a block only if it fits, and report what happened. Returns
    # (added, estimated_tokens) so a caller can say why it refused.
    def offer_block(self, text):
        cost = chunkers.estimate_tokens(text)
        if not self.has_room_for(text):
            return False, cost
        self.add_block(text)
        return True, cost

    # Add a whole file, rendered by its chunker, without checking the budget
    def attach_file(self, path):
        return self.add_block(chunkers.render_file(path))

    # Add a file's outline without its body, without checking the budget
    def attach_outline(self, path):
        return self.add_block(chunkers.outline(path))

    # Add a line range of a file, without checking the budget
    def attach_slice(self, path, start = 0, end = 0):
        return self.add_block(chunkers.slice_lines(path, start, end))

    # Add a named region of a file as its chunker sees it; False when no region matches
    def attach_region(self, path, name):
        text = chunkers.slice_region(path, name)
        if not text:
            return False
        self.add_block(text)
        return True

    ###########################################################
    # Asking
    ###########################################################

    # Send a question with the history to the backend and record the reply; None, with the question dropped, when the request fails
    def ask(self, question, on_text):
        self.messages.append({"role": "user", "content": question})
        try:
            reply = dispatch.call_with_options(
                self.backend.stream, model = self.model, messages = self.messages, temperature = self.temperature,
                max_tokens = self.max_tokens, num_ctx = self.limit, on_text = on_text)
        except (urllib.error.URLError, OSError, http.client.HTTPException, RequestFailed) as error:
            logger.log_error(f"Request failed: {error}")
            self.messages.pop()
            return None
        self.messages.append({"role": "assistant", "content": reply})
        return reply

    # The conversation as Markdown, one heading per message role
    def transcript(self):
        return "\n\n".join(f"## {m['role']}\n\n{m['content']}" for m in self.messages)

###########################################################
# Chat commands
###########################################################

# The slash commands a chat session understands. Kept here rather than in a
# script so any front end -- a REPL, a one-shot runner, something with a
# window -- offers the same vocabulary.
#
# A caller supplies `say` for ordinary output and `warn` for problems, so
# this module does not decide how anything is displayed.

HELP = """
  /model [name]        switch model, or list what the backend offers
  /attach <file>       add a whole file
  /outline <file>      add a map of a file, without its body
  /read <file> [N-M]   add just those lines
  /region <file> <nm>  add a named region, as the filetype's chunker sees it
  /regions <file>      list the region names in a file
  /reset               clear the conversation, keeping the seed
  /save [file]         write the transcript out
  /tokens              context used so far
  /help                this
  /quit                leave
"""

# /help: print the command list
def _command_help(_command, _argument, _session, say, _warn, _window_override):
    say(HELP)

# /model: list the backend's models, marking the current one, or switch to the named model
def _command_model(_command, argument, session, say, _warn, window_override):
    if not argument:
        for name in session.backend.models():
            say(f"  {' *' if name == session.model else '  '} {name}")
    else:
        session.model = argument
        session.limit = window_override or session.backend.context_limit(argument)
        room = f", window {session.limit:,}" if session.limit else ""
        say(f"  model is now {argument}{room}")

# /attach and /outline: add a whole file, or its outline, when it fits the budget
def _command_attach(command, argument, session, say, warn, _window_override):
    if not os.path.isfile(argument):
        warn(f"  no such file: {argument}")
    else:
        text = (chunkers.render_file(argument) if command == "/attach"
                else chunkers.outline(argument))
        added, cost = session.offer_block(text)
        if added:
            say(f"  added {argument} (~{cost:,} tokens)")
        else:
            warn(f"  that is ~{cost:,} tokens and will not fit; "
                 f"try /outline or a narrower /read")

# /read: add a file's N-M line range when it fits the budget
def _command_read(_command, argument, session, say, warn, _window_override):
    bits = argument.split()
    path = bits[0] if bits else ""
    if not os.path.isfile(path):
        warn(f"  no such file: {path}")
        return
    try:
        start, end = chunkers.parse_range(bits[1] if len(bits) > 1 else "")
    except ValueError:
        warn("  range looks like 120-260, 120- or -260")
        return
    added, cost = session.offer_block(chunkers.slice_lines(path, start, end))
    if added:
        say(f"  read {path} (~{cost:,} tokens)")
    else:
        warn(f"  that slice is ~{cost:,} tokens; ask for a narrower range")

# /region: add a file's named region when one matches and it fits the budget
def _command_region(_command, argument, session, say, warn, _window_override):
    bits = argument.split(maxsplit = 1)
    if len(bits) < 2 or not os.path.isfile(bits[0]):
        warn("  usage: /region <file> <region-name>")
        return
    text = chunkers.slice_region(bits[0], bits[1])
    if not text:
        warn(f"  no region matching '{bits[1]}' — try /regions {bits[0]}")
        return
    added, cost = session.offer_block(text)
    say(f"  added region {bits[1]} (~{cost:,} tokens)" if added
        else f"  that region is ~{cost:,} tokens and will not fit")

# /regions: list the first 60 region names in a file
def _command_regions(_command, argument, _session, say, warn, _window_override):
    if not os.path.isfile(argument):
        warn(f"  no such file: {argument}")
    else:
        names = chunkers.list_regions(argument)
        say(f"  {len(names)} regions")
        for name in names[:60]:
            say(f"    {name}")

# /reset: clear the conversation, keeping the seed
def _command_reset(_command, _argument, session, say, _warn, _window_override):
    session.reset()
    say("  conversation reset")

# /save: write the transcript to the named file, transcript.md by default
def _command_save(_command, argument, session, say, warn, _window_override):
    target = argument or "transcript.md"
    if serialization.write_text_file(target, session.transcript()):
        say(f"  wrote {target}")
    else:
        warn(f"  could not write {target}")

# /tokens: report the context used so far, against the window when it is known
def _command_tokens(_command, _argument, session, say, _warn, _window_override):
    room = f" of {session.limit:,}" if session.limit else ""
    say(f"  ~{session.tokens():,}{room} tokens, {len(session.messages)} messages")

# Handler for each slash command other than the quit commands
COMMAND_HANDLERS = {
    "/help": _command_help,
    "/model": _command_model,
    "/attach": _command_attach,
    "/outline": _command_attach,
    "/read": _command_read,
    "/region": _command_region,
    "/regions": _command_regions,
    "/reset": _command_reset,
    "/save": _command_save,
    "/tokens": _command_tokens
}

# Handle one slash command. Returns False when the session should end.
def handle_command(line, session, say, warn, window_override = 0):
    parts = line.strip().split(maxsplit = 1)
    if not parts:
        return True
    command = parts[0]
    argument = parts[1].strip() if len(parts) > 1 else ""

    # Quit
    if command in ("/quit", "/exit", "/q"):
        return False

    # Run the command's handler
    handler = COMMAND_HANDLERS.get(command)
    if handler:
        handler(command, argument, session, say, warn, window_override)

    # Unknown
    else:
        warn(f"  unknown command {command} — try /help")
    return True

###########################################################
# Chat runs
###########################################################

# Print which outline chunker handles which file extensions
def print_chunkers():
    for name, extensions in chunkers.list_chunkers():
        terminal.say(f"  {name:<10} {extensions}")
    return True

# The sampling temperature as a number; None, logged, when it is not a decimal
def _parse_temperature(temperature):
    try:
        return float(temperature)
    except ValueError:
        logger.log_error(f"Temperature must be a decimal such as 0.7, not {temperature}")
        return None

# True when every seed file exists, logging the first one that does not
def _seed_files_exist(seed_files):
    for path in seed_files:
        if not os.path.isfile(path):
            logger.log_error(f"No such file: {path}")
            return False
    return True

# (model, window, system prompt) under the coding preset: the prepared coding model, a 32K
# window unless one is given, and the coding prompt unless one is; None, logged, when the
# preset cannot apply or no model is ready
def _apply_coding_preset(backend_kind, endpoint, model, num_ctx, system, system_file):
    if backend_kind != BACKEND_OLLAMA:
        logger.log_error("--code needs the ollama backend")
        return None
    if endpoint:
        logger.log_error("--code uses [Tools.Ollama] ollama_api_base, so leave out --endpoint")
        return None
    model = get_coding_model(model)
    if not model:
        return None
    num_ctx = num_ctx or CODING_CONTEXT_TOKENS
    if not system and not system_file:
        system = CODING_SYSTEM_PROMPT
    return model, num_ctx, system

# (backend, model) connected to the chosen service, the model defaulting to the first it offers;
# None, logged, when it cannot connect, offers no models or does not offer the model
def connect_backend(backend_kind, endpoint = None, api_key = "", model = None):
    backend = make_backend(backend_kind, endpoint, api_key, model)
    if not backend:
        return None
    available = backend.models()
    if not available:
        logger.log_error(f"No models available from the {backend_kind} backend")
        return None
    model = model or available[0]
    if model not in available and backend_kind != BACKEND_CLAUDE:
        logger.log_error(f"Unknown model {model}. Available: {', '.join(available)}")
        return None
    return backend, model

# A session seeded with the prompt and files; None, logged, when the seed and a reply cannot fit
# the window. A silently truncated context reads as the model ignoring its files, which is worse
# than an error
def _open_seeded_session(backend, model, limit, temperature, max_tokens, seed):
    session = Session(
        backend, model, limit, temperature, max_tokens)
    session.seed_context(*seed)
    if session.seed_overruns():
        logger.log_error(
            f"Seed is ~{session.seed_tokens():,} tokens and the reply needs "
            f"{max_tokens:,}, but the window is {limit:,}.")
        logger.log_error(
            "Use --outline instead of --attach for the large files, or raise --num_ctx.")
        return None
    return session

# Ask one question, streaming the reply under the model's name; False when no reply came
def _ask_in_terminal(session, question):
    terminal.say(terminal.paint(f"\n{session.model}", terminal.GREEN))
    reply = session.ask(question, terminal.write)
    terminal.say("\n")
    return reply is not None

# Chat line by line until the input ends or a command quits, handling slash commands
def _chat_interactively(session, backend_kind, limit, window_override = 0):
    room = f", window {limit:,} tokens" if limit else ""
    terminal.status(f"{session.model} via {backend_kind}{room}")
    if session.seed:
        terminal.status(f"seeded with ~{session.seed_tokens():,} tokens")
    terminal.status("/help for commands, /quit to leave\n")
    while True:
        line = terminal.read_line("you> ")
        if line is None:
            break
        if not line.strip():
            continue
        if line.strip().startswith("/"):
            if not handle_command(line, session, terminal.say, terminal.notice, window_override):
                break
            continue
        _ask_in_terminal(session, line)
    return True

# Answer the one question given or piped in, or else chat interactively
def _converse(session, question, backend_kind, limit, window_override = 0):
    if question:
        return _ask_in_terminal(session, question)
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        return _ask_in_terminal(session, piped) if piped else True
    return _chat_interactively(session, backend_kind, limit, window_override)

# Chat in the terminal with an Ollama, OpenAI-compatible or Claude backend, seeded with a prompt
# and files, or answer one question; False, logged, when an argument or the connection fails
def run_llm_chat(
    backend_kind,
    model = None,
    endpoint = None,
    api_key = "",
    system_file = None,
    system = None,
    attachments = None,
    outlines = None,
    code = False,
    question = None,
    max_tokens = 2048,
    num_ctx = 0,
    temperature = "0.2"):
    temperature = _parse_temperature(temperature)
    if temperature is None:
        return False
    attachments = attachments or []
    outlines = outlines or []
    if not _seed_files_exist(([system_file] if system_file else []) + attachments + outlines):
        return False
    if code:
        preset = _apply_coding_preset(backend_kind, endpoint, model, num_ctx, system, system_file)
        if not preset:
            return False
        model, num_ctx, system = preset
    connection = connect_backend(backend_kind, endpoint, api_key, model)
    if not connection:
        return False
    backend, model = connection
    limit = num_ctx or backend.context_limit(model)
    session = _open_seeded_session(backend, model, limit, temperature, max_tokens, (system_file, system, attachments, outlines))
    if not session:
        return False
    return _converse(session, question, backend_kind, limit, num_ctx)

###########################################################
# Command options
###########################################################

# Declare which service, model, endpoint and API key a chat command talks to
def add_backend_options(parser):
    parser.add_group("Backend")
    parser.add_string_argument(
        args = ("-b", "--backend"),
        default = BACKEND_OLLAMA,
        description = f"Service to talk to: {', '.join(get_backend_keys())}")
    parser.add_string_argument(
        args = ("-m", "--model"),
        description = "Model name; the first one the backend offers when omitted")
    parser.add_string_argument(
        args = ("-e", "--endpoint"),
        description = "Server base URL for the `ollama` and `openai` backends, e.g. `http://localhost:11434`")
    parser.add_string_argument(
        args = ("--api_key",),
        default = os.environ.get("LLM_CHAT_API_KEY", ""),
        description = "Bearer token sent to the `openai` backend; taken from `LLM_CHAT_API_KEY` when omitted")

# Declare the system prompt and the files a chat command seeds its context with
def add_context_options(parser):
    parser.add_group("Context")
    parser.add_string_argument(
        args = ("--system_file",),
        description = "Text file whose contents become the system prompt")
    parser.add_string_argument(
        args = ("--system",),
        description = "System prompt text, appended after `--system_file` when both are given")
    parser.add_string_list_argument(
        args = ("-a", "--attach"),
        description = "File to place in the context whole; repeat for several files")
    parser.add_string_list_argument(
        args = ("-o", "--outline"),
        description = "File to place in the context as an outline of its structure only; repeat for several files")

# Declare a chat command's coding preset, one-shot question, token and context limits,
# temperature and the chunker listing
def add_behavior_options(parser):
    parser.add_group("Behavior")
    parser.add_boolean_argument(
        args = ("-c", "--code"),
        description = "Coding preset for the `ollama` backend: the best coding model the server can hold with a 32K context (pulled and prepared when needed, unless `-m` names one), and a coding system prompt unless one is given")
    parser.add_string_argument(
        args = ("--ask",),
        description = "Ask this one question, print the reply and exit")
    parser.add_integer_argument(
        args = ("--max_tokens",),
        default = 2048,
        description = "Maximum number of tokens in a reply")
    parser.add_integer_argument(
        args = ("--num_ctx",),
        default = 0,
        description = "Context window in tokens: requested from Ollama, and used by every backend to check that the seed and replies fit; `0` takes the model's maximum from Ollama and skips the check elsewhere")
    parser.add_string_argument(
        args = ("-t", "--temperature"),
        default = "0.2",
        description = "Sampling temperature, a decimal such as `0.7`; ignored by the `claude` backend")
    parser.add_boolean_argument(
        args = ("--list_chunkers",),
        description = "Print which outline chunker handles which file extensions, then exit")
