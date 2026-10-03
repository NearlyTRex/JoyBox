# Local imports
from joybox import llmchat


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


def roles(session):
    return [entry["role"] for entry in session.messages]


def run(line, session, output, window_override = 0):
    return llmchat.handle_command(line, session, output.say, output.warn, window_override)
