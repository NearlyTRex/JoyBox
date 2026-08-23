# Imports
import json
import os
import urllib.error
import urllib.request

# Local imports
import joybox.chunkers as chunkers
import joybox.logger as logger
import joybox.ollama as ollama

###########################################################
# Backends
###########################################################

# A backend turns a message list into streamed text. Adding one means
# implementing stream() and listing what models it offers, so the session
# and the calling script stay backend-agnostic.

BACKEND_OLLAMA = "ollama"
BACKEND_OPENAI = "openai"
BACKEND_CLAUDE = "claude"

# Ollama, via its native chat route
#
# The OpenAI-compatible route it also serves cannot set the context window,
# and the runtime default sits far below what a model supports. It then
# truncates without saying so, which reads as the model ignoring your files.
# The native route accepts num_ctx, so that is what is used here.
class OllamaBackend:
    kind = BACKEND_OLLAMA

    def __init__(self, endpoint = None):
        self.endpoint = endpoint or ollama.get_api_base()

    def models(self):
        try:
            with urllib.request.urlopen(f"{self.endpoint}/v1/models", timeout = 10) as response:
                payload = json.loads(response.read().decode())
            return [entry["id"] for entry in payload.get("data", [])]
        except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError):
            return []

    def context_limit(self, model):
        try:
            request = urllib.request.Request(
                f"{self.endpoint}/api/show",
                data = json.dumps({"name": model}).encode(),
                headers = {"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout = 10) as response:
                info = json.loads(response.read().decode())
            for key, value in (info.get("model_info") or {}).items():
                if key.endswith(".context_length"):
                    return int(value)
        except (urllib.error.URLError, OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
        return 0

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
                try:
                    body = json.loads(line)
                except json.JSONDecodeError:
                    continue
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

    def headers(self):
        out = {"Content-Type": "application/json"}
        if self.api_key:
            out["Authorization"] = f"Bearer {self.api_key}"
        return out

    def models(self):
        try:
            request = urllib.request.Request(f"{self.endpoint}/v1/models", headers = self.headers())
            with urllib.request.urlopen(request, timeout = 10) as response:
                payload = json.loads(response.read().decode())
            return [entry["id"] for entry in payload.get("data", [])]
        except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError):
            return []

    def context_limit(self, model):
        return 0

    def stream(self, model, messages, temperature, max_tokens, num_ctx, on_text):
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
                try:
                    delta = json.loads(body)["choices"][0].get("delta", {})
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue
                piece = delta.get("content")
                if piece:
                    parts.append(piece)
                    on_text(piece)
        return "".join(parts)

# Claude, through the existing joybox.claude wrapper
#
# That wrapper is one-shot rather than streaming, so the whole reply arrives
# at once. The conversation is flattened into a single prompt, since the
# wrapper takes a prompt and a system prompt rather than a message list.
class ClaudeBackend:
    kind = BACKEND_CLAUDE

    def __init__(self, model = None):
        import joybox.claude as claude
        self.claude = claude
        self.model = model or claude.DEFAULT_MODEL

    def models(self):
        return [self.model]

    def context_limit(self, model):
        return 0

    def flatten(self, messages):
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        turns = []
        for message in messages:
            if message["role"] == "system":
                continue
            who = "Human" if message["role"] == "user" else "Assistant"
            turns.append(f"{who}: {message['content']}")
        return system, "\n\n".join(turns) + "\n\nAssistant:"

    def stream(self, model, messages, temperature, max_tokens, num_ctx, on_text):
        system, prompt = self.flatten(messages)
        reply = self.claude.send_message(
            prompt = prompt,
            model = model or self.model,
            max_tokens = max_tokens,
            system_prompt = system or None)
        reply = reply or ""
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

    def reset(self):
        self.messages = list(self.seed)

    ###########################################################
    # Budget
    ###########################################################
    def tokens(self):
        return chunkers.estimate_tokens("".join(m["content"] for m in self.messages))

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

    def attach_file(self, path):
        return self.add_block(chunkers.render_file(path))

    def attach_outline(self, path):
        return self.add_block(chunkers.outline(path))

    def attach_slice(self, path, start = 0, end = 0):
        return self.add_block(chunkers.slice_lines(path, start, end))

    def attach_region(self, path, name):
        text = chunkers.slice_region(path, name)
        if not text:
            return False
        self.add_block(text)
        return True

    ###########################################################
    # Asking
    ###########################################################
    def ask(self, question, on_text):
        self.messages.append({"role": "user", "content": question})
        try:
            reply = self.backend.stream(self.model, self.messages, self.temperature,
                                        self.max_tokens, self.limit, on_text)
        except (urllib.error.URLError, OSError) as error:
            logger.log_error(f"Request failed: {error}")
            self.messages.pop()
            return None
        self.messages.append({"role": "assistant", "content": reply})
        return reply

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

# Handle one slash command. Returns False when the session should end.
def handle_command(line, session, say, warn, window_override = 0):
    parts = line.strip().split(maxsplit = 1)
    command = parts[0]
    argument = parts[1].strip() if len(parts) > 1 else ""

    # Quit
    if command in ("/quit", "/exit", "/q"):
        return False

    # Help
    if command == "/help":
        say(HELP)

    # Change model
    elif command == "/model":
        if not argument:
            for name in session.backend.models():
                say(f"  {' *' if name == session.model else '  '} {name}")
        else:
            session.model = argument
            session.limit = window_override or session.backend.context_limit(argument)
            room = f", window {session.limit:,}" if session.limit else ""
            say(f"  model is now {argument}{room}")

    # Attach file
    elif command in ("/attach", "/outline"):
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

    # Read file
    elif command == "/read":
        bits = argument.split()
        path = bits[0] if bits else ""
        if not os.path.isfile(path):
            warn(f"  no such file: {path}")
        else:
            try:
                start, end = chunkers.parse_range(bits[1] if len(bits) > 1 else "")
            except ValueError:
                warn("  range looks like 120-260, 120- or -260")
                return True
            added, cost = session.offer_block(chunkers.slice_lines(path, start, end))
            if added:
                say(f"  read {path} (~{cost:,} tokens)")
            else:
                warn(f"  that slice is ~{cost:,} tokens; ask for a narrower range")

    # Slice region
    elif command == "/region":
        bits = argument.split(maxsplit = 1)
        if len(bits) < 2 or not os.path.isfile(bits[0]):
            warn("  usage: /region <file> <region-name>")
        else:
            text = chunkers.slice_region(bits[0], bits[1])
            if not text:
                warn(f"  no region matching '{bits[1]}' — try /regions {bits[0]}")
            else:
                added, cost = session.offer_block(text)
                say(f"  added region {bits[1]} (~{cost:,} tokens)" if added
                    else f"  that region is ~{cost:,} tokens and will not fit")

    # List regions
    elif command == "/regions":
        if not os.path.isfile(argument):
            warn(f"  no such file: {argument}")
        else:
            names = chunkers.list_regions(argument)
            say(f"  {len(names)} regions")
            for name in names[:60]:
                say(f"    {name}")

    # Reset
    elif command == "/reset":
        session.reset()
        say("  conversation reset")

    # Save transcript
    elif command == "/save":
        target = argument or "transcript.md"
        with open(target, "w", encoding = "utf-8") as handle:
            handle.write(session.transcript())
        say(f"  wrote {target}")

    # List tokens
    elif command == "/tokens":
        room = f" of {session.limit:,}" if session.limit else ""
        say(f"  ~{session.tokens():,}{room} tokens, {len(session.messages)} messages")

    # Unknown
    else:
        warn(f"  unknown command {command} — try /help")
    return True
