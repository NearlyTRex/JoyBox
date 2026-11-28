# Imports
import importlib
import os
import os.path

# Local imports
from joybox import fileops
from joybox import settings
from joybox import logger
from joybox import paths
from joybox import serialization

# Get anthropic, imported on first use
def _get_anthropic():
    return importlib.import_module("anthropic")

# Default model
DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_MAX_TOKENS = 8192

# Get API key from ini
def get_api_key():
    api_key = settings.get_value("UserData.Anthropic", "anthropic_api_key", throw_exception=False)
    if not api_key:
        return None
    return api_key

# Check if API key is configured
def is_configured():
    return get_api_key() is not None

# Create Anthropic client
def create_client():
    try:
        anthropic_lib = _get_anthropic()
    except ImportError:
        logger.log_error("Anthropic not installed")
        return None
    api_key = get_api_key()
    if not api_key:
        logger.log_error("Anthropic API key not configured in JoyBox.ini")
        return None
    return anthropic_lib.Anthropic(api_key=api_key)

# The messages.create parameters for one user prompt, with the system prompt when given
def _build_message_params(prompt, model, max_tokens, system_prompt):
    params = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    if system_prompt:
        params["system"] = system_prompt
    return params

# A friendly warning for an API error: credits, key, rate limit, overload, or the error itself
def _describe_api_error(error_str):
    if "credit balance is too low" in error_str:
        return "Anthropic API: Insufficient credits. Add credits at https://console.anthropic.com/settings/billing"
    if "invalid_api_key" in error_str or "authentication" in error_str.lower():
        return "Anthropic API: Invalid API key. Check your key in JoyBox.ini"
    if "rate_limit" in error_str.lower():
        return "Anthropic API: Rate limited. Please wait and try again"
    if "overloaded" in error_str.lower():
        return "Anthropic API: Service overloaded. Please try again later"
    return "Anthropic API error: %s" % error_str

# Send message to Claude
def send_message(
    prompt,
    model = None,
    max_tokens = None,
    system_prompt = None,
    verbose = False):

    # Set defaults
    if not model:
        model = DEFAULT_MODEL
    if not max_tokens:
        max_tokens = DEFAULT_MAX_TOKENS

    # Create client
    client = create_client()
    if not client:
        return None
    anthropic_lib = _get_anthropic()

    try:
        # Build message parameters
        params = _build_message_params(prompt, model, max_tokens, system_prompt)

        # Send request
        if verbose:
            logger.log_info("Sending request to %s (max_tokens=%d)" % (model, max_tokens))
        response = client.messages.create(**params)

        # Extract text from response
        if response.content and len(response.content) > 0:
            return response.content[0].text
        return None

    # Extract friendly error message from API errors
    except anthropic_lib.APIError as e:
        logger.log_warning(_describe_api_error(str(e)))
        return None

# Process a file with a prompt template
def process_file(
    input_file,
    prompt_template,
    input_dir = None,
    output_dir = None,
    model = None,
    max_tokens = None,
    system_prompt = None,
    verbose = False):

    # Read file content
    file_content = serialization.read_text_file(input_file)
    if file_content is None:
        return None

    # Get filename components
    filename = os.path.basename(input_file)
    file_basename = paths.get_filename_basename(input_file)
    file_extension = paths.get_filename_extension(input_file)

    # Substitute variables in prompt
    prompt = prompt_template
    prompt = prompt.replace("{file_content}", file_content)
    prompt = prompt.replace("{filename}", filename)
    prompt = prompt.replace("{file_basename}", file_basename)
    prompt = prompt.replace("{file_extension}", file_extension)
    prompt = prompt.replace("{input_file}", input_file)
    if input_dir:
        prompt = prompt.replace("{input_dir}", input_dir)
    if output_dir:
        prompt = prompt.replace("{output_dir}", output_dir)

    # Send to Claude
    return send_message(
        prompt = prompt,
        model = model,
        max_tokens = max_tokens,
        system_prompt = system_prompt,
        verbose = verbose)

# The files under input_path to process, only those with the given extensions when there are any
def _get_files_to_process(input_path, extensions):
    if extensions:
        return paths.build_file_list_by_extensions(input_path, extensions = extensions)
    return paths.build_file_list(input_path)

# Write Claude's result to the output file, making its directory first; whether the write worked
def _write_result_file(output_file, result, verbose):
    output_dir = os.path.dirname(output_file)
    if not paths.does_path_exist(output_dir):
        fileops.make_directory(
            src = output_dir,
            verbose = verbose)
    return serialization.write_text_file(
        src = output_file,
        contents = result,
        verbose = verbose)

# Process one file into the same relative spot under output_path; "success", "skip" or "error"
def _process_one_file(input_file, input_path, output_path, prompt_template, model, max_tokens, system_prompt, skip_existing, verbose, pretend_run):

    # Calculate relative path and output path
    rel_path = os.path.relpath(input_file, input_path)
    output_file = os.path.join(output_path, rel_path)

    # Skip if exists and skip_existing is set
    if skip_existing and paths.does_path_exist(output_file):
        if verbose:
            logger.log_info("Skipping (exists): %s" % rel_path)
        return "skip"

    # Start processing file
    logger.log_info("Processing: %s" % rel_path)
    if pretend_run:
        logger.log_info("  Would write to: %s" % output_file)
        return "success"

    # Process file with Claude
    result = process_file(
        input_file = input_file,
        prompt_template = prompt_template,
        input_dir = input_path,
        output_dir = output_path,
        model = model,
        max_tokens = max_tokens,
        system_prompt = system_prompt,
        verbose = verbose)
    if result is None:
        logger.log_warning("Failed to process: %s" % rel_path)
        return "error"

    # Write output file
    return "success" if _write_result_file(output_file, result, verbose) else "error"

# Process each file in turn; (success, skip, error) counts
def _process_each_file(files_to_process, input_path, output_path, prompt_template, model, max_tokens, system_prompt, skip_existing, verbose, pretend_run):
    counts = {"success": 0, "skip": 0, "error": 0}
    for input_file in files_to_process:
        status = _process_one_file(
            input_file, input_path, output_path, prompt_template, model, max_tokens, system_prompt,
            skip_existing, verbose, pretend_run)
        counts[status] += 1
    return (counts["success"], counts["skip"], counts["error"])

# Process multiple files with a prompt file
def process_files(
    input_path,
    output_path,
    prompt_file,
    extensions = None,
    model = None,
    max_tokens = None,
    system_prompt = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False):

    # Get extensions
    extensions = [] if extensions is None else extensions

    # Read prompt template
    prompt_template = serialization.read_text_file(prompt_file)
    if prompt_template is None:
        logger.log_error("Failed to read prompt file: %s" % prompt_file)
        return (0, 0, 0)

    # Build file list
    files_to_process = _get_files_to_process(input_path, extensions)
    if not files_to_process:
        logger.log_warning("No files found to process")
        return (0, 0, 0)

    # Create output directory if needed
    if not paths.does_path_exist(output_path):
        fileops.make_directory(
            src = output_path,
            verbose = verbose,
            pretend_run = pretend_run)

    # Process files
    return _process_each_file(
        files_to_process, input_path, output_path, prompt_template, model, max_tokens, system_prompt,
        skip_existing, verbose, pretend_run)

# Quit unless the prompt file is given and exists, and, outside a pretend run, an API key is set
def check_process_requirements(prompt_file, pretend_run = False):
    if not prompt_file:
        logger.log_error("Prompt file is required (-f/--prompt_file)", quit_program = True)
    if not paths.does_path_exist(prompt_file):
        logger.log_error("Prompt file not found: %s" % prompt_file, quit_program = True)
    if not pretend_run and not is_configured():
        logger.log_error("Anthropic API key not configured", quit_program = True)

# The comma-separated extensions as a list, blanks dropped and each starting with a dot
def parse_extensions(extensions_text):
    if not extensions_text:
        return []
    extensions = [ext.strip() for ext in extensions_text.split(",") if ext.strip()]
    return [ext if ext.startswith(".") else "." + ext for ext in extensions]

# The preview lines for a process_files run, counting the files it would send
def get_process_preview_details(input_path, output_path, prompt_file, model, extensions):
    file_count = len(_get_files_to_process(input_path, extensions))
    details = [
        "Input: %s" % input_path,
        "Output: %s" % output_path,
        "Prompt: %s" % prompt_file,
        "Model: %s" % model,
        "Files: %d" % file_count
    ]
    if extensions:
        details.append("Extensions: %s" % ", ".join(extensions))
    return details

# Run process_files and log its counts, as a warning when any file failed
def process_files_with_summary(
    input_path,
    output_path,
    prompt_file,
    extensions = None,
    model = None,
    max_tokens = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False):
    success_count, skip_count, error_count = process_files(
        input_path = input_path,
        output_path = output_path,
        prompt_file = prompt_file,
        extensions = extensions,
        model = model,
        max_tokens = max_tokens,
        skip_existing = skip_existing,
        verbose = verbose,
        pretend_run = pretend_run)
    summary = "Completed: %d success, %d skipped, %d errors" % (success_count, skip_count, error_count)
    if error_count > 0:
        logger.log_warning(summary)
    else:
        logger.log_info(summary)
