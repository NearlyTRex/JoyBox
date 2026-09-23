#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.arguments as arguments
import joybox.chunkers as chunkers
import joybox.llmchat as llmchat
import joybox.logger as logger
import joybox.setup as setup
import joybox.system as system
import joybox.terminal as terminal

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Interactive chat with a local or cloud LLM, seeded with a prompt and files.",
    details = (
        "Opens a chat in the terminal against one of three backends: `ollama` (the native\n"
        "Ollama chat route, at `[Tools.Ollama] ollama_api_base` in `~/JoyBox.ini` unless\n"
        "`--endpoint` is given), `openai` (any OpenAI-compatible server such as llama.cpp's,\n"
        "`http://localhost:8080` unless `--endpoint` is given), or `claude` (the Anthropic API,\n"
        "using the key at `[UserData.Anthropic] anthropic_api_key`). Replies stream as they\n"
        "arrive, except with `claude`, which returns each reply whole.\n"
        "\n"
        "The conversation can be seeded before the first question: a system prompt from\n"
        "`--system_file` and `--system`, whole files with `--attach`, and outlines with\n"
        "`--outline`. An outline is a map of a file's structure without its body (functions,\n"
        "labels, headings or keys, depending on the file type), which keeps a large corpus\n"
        "within the context window. `--list_chunkers` shows which file types get a structural\n"
        "outline; anything else is outlined by line.\n"
        "\n"
        "With `--ask`, or with a question piped on standard input, it answers once and exits.\n"
        "Otherwise it reads questions interactively. Commands in the chat: `/model [name]`\n"
        "switches or lists models, `/attach <file>` and `/outline <file>` add a file,\n"
        "`/read <file> [N-M]` adds a line range, `/region <file> <name>` adds one named region\n"
        "and `/regions <file>` lists them, `/reset` clears everything but the seed,\n"
        "`/save [file]` writes the transcript (`transcript.md` by default), `/tokens` shows\n"
        "context use, `/help` lists the commands and `/quit` leaves."),
    examples = [
        ("Chat with the first model the local Ollama server offers", "llm_chat"),
        ("Ask one question about a file and exit", "llm_chat -m qwen2.5-coder:7b -a main.c --ask \"What does parse_header do?\""),
        ("Seed a system prompt, one whole file and the outline of a large one", "llm_chat --system_file review.md -a player.cpp -o game.asm"),
        ("Answer a question piped in on standard input", "llm_chat -a notes.md < question.txt"),
        ("Use a llama.cpp server, checking the seed against its 32K window", "llm_chat -b openai -e http://localhost:8080 --num_ctx 32768 -o engine.c"),
        ("Chat with Claude", "llm_chat -b claude -m claude-sonnet-4-20250514"),
        ("Show which file types get a structural outline", "llm_chat --list_chunkers"),
    ],
    notes = [
        "If the system prompt and attached files plus `--max_tokens` do not fit the context window, it refuses to start rather than let the server truncate silently. Use `--outline` for the large files or raise `--num_ctx`.",
        "Token counts are estimates (about 3.6 characters per token).",
        "With `ollama` or `openai`, the model must be one the server lists. With `claude` any model id is accepted and no window check is made.",
        "`--api_key` defaults to the `LLM_CHAT_API_KEY` environment variable.",
        "`-o` is `--outline` here, not an output path.",
    ],
    see_also = ["ollama_tool", "claude_tool", "decompiler_tool"],
    section = "AI")
parser.add_group("Backend")
parser.add_string_argument(
    args = ("-b", "--backend"),
    default = llmchat.BACKEND_OLLAMA,
    description = f"Service to talk to: {', '.join(llmchat.get_backend_keys())}")
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
parser.add_group("Behavior")
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
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

###########################################################
# Main
###########################################################
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Show the chunker registry and leave
    if args.list_chunkers:
        for name, extensions in chunkers.list_chunkers():
            print(f"  {name:<10} {extensions}")
        return True

    # Connect
    backend = llmchat.make_backend(args.backend, args.endpoint, args.api_key, args.model)
    if not backend:
        return False
    available = backend.models()
    if not available:
        logger.log_error(f"No models available from the {args.backend} backend")
        return False
    model = args.model or available[0]
    if model not in available and args.backend != llmchat.BACKEND_CLAUDE:
        logger.log_error(f"Unknown model {model}. Available: {', '.join(available)}")
        return False

    # Check the files before spending anything on a request
    attachments = args.attach or []
    outlines = args.outline or []
    for path in attachments + outlines:
        if not os.path.isfile(path):
            logger.log_error(f"No such file: {path}")
            return False

    # Size the window to the model unless told otherwise
    limit = args.num_ctx or backend.context_limit(model)
    session = llmchat.Session(
        backend, model, limit, float(args.temperature), args.max_tokens)
    session.seed_context(args.system_file, args.system, attachments, outlines)

    # Refuse a seed that cannot fit. A silently truncated context reads as
    # the model ignoring its files, which is worse than an error.
    if session.seed_overruns():
        logger.log_error(
            f"Seed is ~{session.seed_tokens():,} tokens and the reply needs "
            f"{args.max_tokens:,}, but the window is {limit:,}.")
        logger.log_error(
            "Use --outline instead of --attach for the large files, or raise --num_ctx.")
        return False

    # Ask question in terminal
    def ask(question):
        print(terminal.paint(f"\n{session.model}", terminal.GREEN))
        session.ask(question, terminal.write)
        print("\n")

    # One-shot, for --ask or a pipe
    if args.ask:
        ask(args.ask)
        return True
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            ask(piped)
        return True

    # Interactive
    room = f", window {limit:,} tokens" if limit else ""
    terminal.status(f"{session.model} via {args.backend}{room}")
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
            if not llmchat.handle_command(line, session, print, terminal.notice, args.num_ctx):
                break
            continue
        ask(line)

    return True

###########################################################
# Start
###########################################################
if __name__ == "__main__":
    system.run_main(main)
