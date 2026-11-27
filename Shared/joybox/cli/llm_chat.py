# Imports
from joybox import arguments
from joybox import llmchat
from joybox import logger
from joybox import setup
from joybox import system

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "llm_chat")
    llmchat.add_backend_options(parser)
    llmchat.add_context_options(parser)
    llmchat.add_behavior_options(parser)
    parser.add_common_arguments()
    return parser

###########################################################
# Main
###########################################################

# Chat in the terminal with an Ollama, OpenAI-compatible or Claude backend, seeded with a prompt and files, or answer one question and exit
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Show the chunker registry and leave
    if args.list_chunkers:
        return llmchat.print_chunkers()

    # Chat, or answer one question
    return llmchat.run_llm_chat(
        backend_kind = args.backend,
        model = args.model,
        endpoint = args.endpoint,
        api_key = args.api_key,
        system_file = args.system_file,
        system = args.system,
        attachments = args.attach,
        outlines = args.outline,
        code = args.code,
        question = args.ask,
        max_tokens = args.max_tokens,
        num_ctx = args.num_ctx,
        temperature = args.temperature)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
