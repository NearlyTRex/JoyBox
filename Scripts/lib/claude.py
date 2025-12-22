# Imports
import os, os.path
import sys

# Local imports
import fileops
import ini
import system
import logger
import paths
import serialization

# Default model
DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_MAX_TOKENS = 8192

# Get API key from ini
def get_api_key():
    api_key = ini.get_ini_value("UserData.Anthropic", "anthropic_api_key", throw_exception=False)
    if not api_key:
        return None
    return api_key

# Check if API key is configured
def is_configured():
    return get_api_key() is not None

# Create Anthropic client
def create_client():
    try:
        import anthropic as anthropic_lib
    except ImportError:
        logger.log_error("Anthropic not installed")
        return None
    api_key = get_api_key()
    if not api_key:
        logger.log_error("Anthropic API key not configured in JoyBox.ini")
        return None
    return anthropic_lib.Anthropic(api_key=api_key)

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

    try:
        # Build message parameters
        params = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        # Add system prompt if provided
        if system_prompt:
            params["system"] = system_prompt

        # Send request
        if verbose:
            logger.log_info("Sending request to %s (max_tokens=%d)" % (model, max_tokens))
        response = client.messages.create(**params)

        # Extract text from response
        if response.content and len(response.content) > 0:
            return response.content[0].text
        return None

    # Extract friendly error message from API errors
    except Exception as e:
        error_str = str(e)
        if "credit balance is too low" in error_str:
            logger.log_warning("Anthropic API: Insufficient credits. Add credits at https://console.anthropic.com/settings/billing")
        elif "invalid_api_key" in error_str or "authentication" in error_str.lower():
            logger.log_warning("Anthropic API: Invalid API key. Check your key in JoyBox.ini")
        elif "rate_limit" in error_str.lower():
            logger.log_warning("Anthropic API: Rate limited. Please wait and try again")
        elif "overloaded" in error_str.lower():
            logger.log_warning("Anthropic API: Service overloaded. Please try again later")
        else:
            logger.log_warning("Anthropic API error: %s" % error_str)
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

# Process multiple files with a prompt file
def process_files(
    input_path,
    output_path,
    prompt_file,
    extensions = [],
    model = None,
    max_tokens = None,
    system_prompt = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False):

    # Read prompt template
    prompt_template = serialization.read_text_file(prompt_file)
    if prompt_template is None:
        logger.log_error("Failed to read prompt file: %s" % prompt_file)
        return (0, 0, 0)

    # Build file list
    if extensions:
        files_to_process = paths.build_file_list_by_extensions(input_path, extensions = extensions)
    else:
        files_to_process = paths.build_file_list(input_path)
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
    success_count = 0
    skip_count = 0
    error_count = 0
    for input_file in files_to_process:

        # Calculate relative path and output path
        rel_path = os.path.relpath(input_file, input_path)
        output_file = os.path.join(output_path, rel_path)
        output_dir = os.path.dirname(output_file)

        # Skip if exists and skip_existing is set
        if skip_existing and paths.does_path_exist(output_file):
            if verbose:
                logger.log_info("Skipping (exists): %s" % rel_path)
            skip_count += 1
            continue

        # Start processing file
        logger.log_info("Processing: %s" % rel_path)
        if pretend_run:
            logger.log_info("  Would write to: %s" % output_file)
            success_count += 1
            continue

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
            error_count += 1
            continue

        # Create output directory if needed
        if not paths.does_path_exist(output_dir):
            fileops.make_directory(
                src = output_dir,
                verbose = verbose)

        # Write output file
        success = serialization.write_text_file(
            src = output_file,
            contents = result,
            verbose = verbose)
        if success:
            success_count += 1
        else:
            error_count += 1
    return (success_count, skip_count, error_count)
