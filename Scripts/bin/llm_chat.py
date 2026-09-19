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
    description = "Interactive chat with a local or cloud LLM, seeded with a prompt and files.")
parser.add_string_argument(
    args = ("-b", "--backend"),
    default = llmchat.BACKEND_OLLAMA,
    description = f"Service to talk to ({', '.join(llmchat.get_backend_keys())})")
parser.add_string_argument(
    args = ("-m", "--model"),
    description = "Model name (default: the first one offered)")
parser.add_string_argument(
    args = ("-e", "--endpoint"),
    description = "Endpoint URL, for the ollama and openai backends")
parser.add_string_argument(
    args = ("--api_key",),
    default = os.environ.get("LLM_CHAT_API_KEY", ""),
    description = "Bearer token, for the openai backend")
parser.add_string_argument(
    args = ("--system_file",),
    description = "File holding the system prompt")
parser.add_string_argument(
    args = ("--system",),
    description = "Extra system prompt text")
parser.add_string_list_argument(
    args = ("-a", "--attach"),
    description = "File to place in context whole; repeatable")
parser.add_string_list_argument(
    args = ("-o", "--outline"),
    description = "File to place in context as a map only; repeatable")
parser.add_string_argument(
    args = ("--ask",),
    description = "Ask one question and exit")
parser.add_integer_argument(
    args = ("--max_tokens",),
    default = 2048,
    description = "Maximum tokens in a reply")
parser.add_integer_argument(
    args = ("--num_ctx",),
    default = 0,
    description = "Context window to request (default: the model's maximum)")
parser.add_string_argument(
    args = ("-t", "--temperature"),
    default = "0.2",
    description = "Sampling temperature")
parser.add_boolean_argument(
    args = ("--list_chunkers",),
    description = "Show which chunker handles which filetype and exit")
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
