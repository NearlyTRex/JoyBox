# Imports
import os
import re

# Local imports
from joybox import validation
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import command
from joybox import programs
from joybox import serialization
from joybox import settings
from joybox import runtime

# Extract activation bytes from text (finds 8 hex character sequence)
def extract_activation_bytes(text):
    if not text:
        return None
    match = re.search(r'\b([0-9a-fA-F]{8})\b', text)
    if match:
        return match.group(1)
    return None

# The 8-hex-digit Audible key from the settings, the given authcode file, $AUDIBLE_ACTIVATION_BYTES
# or ~/.audible_authcode, in that order; None when none has one
def get_activation_bytes(authcode_file = None, verbose = False, exit_on_failure = False):

    # Check ini file first
    authcode = settings.get_value("UserData.Audible", "audible_activation_bytes")
    if authcode:
        extracted = extract_activation_bytes(authcode)
        if extracted:
            return extracted

    # Check authcode file
    if authcode_file and paths.is_path_file(authcode_file):
        authcode = serialization.read_text_file(
            src = authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if authcode:
            extracted = extract_activation_bytes(authcode)
            if extracted:
                return extracted

    # Check environment variable
    authcode = os.environ.get("AUDIBLE_ACTIVATION_BYTES")
    if authcode:
        extracted = extract_activation_bytes(authcode)
        if extracted:
            return extracted

    # Check default location
    default_authcode_file = paths.join_paths(runtime.get_home_directory(), ".audible_authcode")
    if paths.is_path_file(default_authcode_file):
        authcode = serialization.read_text_file(
            src = default_authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if authcode:
            extracted = extract_activation_bytes(authcode)
            if extracted:
                return extracted
    return None

# Log the error when given and quit when asked to; always False, for the caller to return
def _fail(message, exit_on_failure):
    if message:
        logger.log_error(message)
    if exit_on_failure:
        runtime.quit_program()
    return False

# The given activation bytes, else the ones found by get_activation_bytes
def _resolve_activation_bytes(activation_bytes, authcode_file, verbose, exit_on_failure):
    if not activation_bytes:
        activation_bytes = get_activation_bytes(
            authcode_file = authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    return activation_bytes

# Whether the input is an existing .aax or .aa file, logging which check failed
def _check_aax_input_file(input_file, exit_on_failure):

    # Validate input file
    validation.assert_is_valid_path(input_file, "input_file")
    if not paths.is_path_file(input_file):
        return _fail(f"Input file does not exist: {input_file}", exit_on_failure)

    # Check file extension
    input_ext = paths.get_filename_extension(input_file).lower()
    if input_ext not in [".aax", ".aa"]:
        return _fail(f"Input file must be .aax or .aa format: {input_file}", exit_on_failure)
    return True

# Whether the activation bytes are present and 8 hex characters, logging which check failed
def _check_activation_bytes(activation_bytes, exit_on_failure):
    if not activation_bytes:
        return _fail("Activation bytes not provided or found in environment", exit_on_failure)
    if len(activation_bytes) != 8 or not all(c in '0123456789abcdefABCDEF' for c in activation_bytes):
        return _fail(
            f"Invalid activation bytes format. Expected 8 hex characters, got: {activation_bytes}",
            exit_on_failure)
    return True

# Make the directory when it is named and missing
def _make_missing_directory(directory, verbose, pretend_run, exit_on_failure):
    if directory and not paths.is_path_directory(directory):
        fileops.make_directory(
            src = directory,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# FFMpeg command that copies the decrypted streams, overwriting the output only when asked
def _build_ffmpeg_decrypt_command(ffmpeg_tool, input_file, output_file, activation_bytes, overwrite):

    # -activation_bytes: The Audible activation bytes for decryption
    # -i: Input file
    # -c copy: Copy streams without re-encoding (preserves quality and chapters)
    # -vn: Disable video (removes cover art stream if present, but keeps audio)
    return [
        ffmpeg_tool,
        "-activation_bytes", activation_bytes,
        "-i", input_file,
        "-c", "copy",
        "-y" if overwrite else "-n",
        output_file
    ]

# Find FFMpeg, make the output file's directory, then decrypt into it; False on failure
def _run_ffmpeg_decrypt(
    input_file,
    output_file,
    activation_bytes,
    overwrite,
    verbose,
    pretend_run,
    exit_on_failure):

    # Check for FFMpeg
    ffmpeg_tool = programs.find_tool_program("FFMpeg")
    if not ffmpeg_tool:
        return _fail(None, exit_on_failure)

    # Log operation
    logger.log_info(f"Decrypting AAX file: {input_file}")
    logger.log_info(f"Output file: {output_file}")

    # Create output directory if needed
    _make_missing_directory(paths.get_filename_directory(output_file), verbose, pretend_run, exit_on_failure)

    # Build FFMpeg command
    ffmpeg_cmd = _build_ffmpeg_decrypt_command(ffmpeg_tool, input_file, output_file, activation_bytes, overwrite)

    # Run FFMpeg
    if not pretend_run:
        code = command.run_returncode_command(
            cmd = ffmpeg_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return _fail(f"FFMpeg decryption failed with code {code}", exit_on_failure)
    logger.log_info(f"Successfully decrypted: {output_file}")
    return True

# Decrypt AAX file to M4A using FFMpeg
def decrypt_aax_to_m4a(
    input_file,
    output_file = None,
    activation_bytes = None,
    authcode_file = None,
    overwrite = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate input file
    if not _check_aax_input_file(input_file, exit_on_failure):
        return False

    # Determine output file
    if not output_file:
        output_file = paths.change_filename_extension(input_file, ".m4a")

    # Check if output already exists
    if paths.is_path_file(output_file) and not overwrite:
        logger.log_warning(f"Output file already exists, skipping: {output_file}")
        return True

    # Get activation bytes
    activation_bytes = _resolve_activation_bytes(activation_bytes, authcode_file, verbose, exit_on_failure)
    if not _check_activation_bytes(activation_bytes, exit_on_failure):
        return False

    # Decrypt
    return _run_ffmpeg_decrypt(
        input_file = input_file,
        output_file = output_file,
        activation_bytes = activation_bytes,
        overwrite = overwrite,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The .m4a path in output_dir named after the input file; None without an output_dir
def _get_m4a_output_file(input_file, output_dir):
    if not output_dir:
        return None
    filename = paths.get_filename_file(input_file)
    filename = paths.change_filename_extension(filename, ".m4a")
    return paths.join_paths(output_dir, filename)

# Decrypt multiple AAX files to M4A
def decrypt_aax_files_to_m4a(
    input_files,
    output_dir = None,
    activation_bytes = None,
    authcode_file = None,
    overwrite = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate input
    if not input_files:
        return _fail("No input files provided", exit_on_failure)

    # Get activation bytes once for all files
    activation_bytes = _resolve_activation_bytes(activation_bytes, authcode_file, verbose, exit_on_failure)
    if not activation_bytes:
        return _fail("Activation bytes not provided", exit_on_failure)

    # Process each file
    success_count, fail_count = _decrypt_each_file(
        input_files = input_files,
        output_dir = output_dir,
        activation_bytes = activation_bytes,
        overwrite = overwrite,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Log summary
    logger.log_info(f"Decryption complete: {success_count} succeeded, {fail_count} failed")
    return fail_count == 0

# Decrypt each file in turn, quitting on the first failure when asked; (succeeded, failed) counts
def _decrypt_each_file(input_files, output_dir, activation_bytes, overwrite, verbose, pretend_run, exit_on_failure):
    success_count = 0
    fail_count = 0
    for input_file in input_files:

        # Decrypt file
        success = decrypt_aax_to_m4a(
            input_file = input_file,
            output_file = _get_m4a_output_file(input_file, output_dir),
            activation_bytes = activation_bytes,
            overwrite = overwrite,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if success:
            success_count += 1
        else:
            fail_count += 1
            if exit_on_failure:
                logger.log_error(f"Failed to decrypt: {input_file}")
                runtime.quit_program()
    return success_count, fail_count

# Whether the name ends in .aax or .aa, in any case
def _is_aax_filename(filename):
    return filename.lower().endswith((".aax", ".aa"))

# The .aax and .aa files in the directory, or under it when recursive
def _find_aax_files(input_dir, recursive):
    aax_files = []
    if recursive:
        for root, _, files in os.walk(input_dir):
            for filename in filter(_is_aax_filename, files):
                aax_files.append(paths.join_paths(root, filename))
    else:
        for item in paths.get_directory_contents(input_dir):
            if _is_aax_filename(item):
                aax_files.append(paths.join_paths(input_dir, item))
    return aax_files

# Decrypt all AAX files in a directory
def decrypt_aax_directory(
    input_dir,
    output_dir = None,
    activation_bytes = None,
    authcode_file = None,
    recursive = False,
    overwrite = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate input directory
    validation.assert_is_valid_path(input_dir, "input_dir")
    if not paths.is_path_directory(input_dir):
        return _fail(f"Input directory does not exist: {input_dir}", exit_on_failure)

    # Use input directory as output if not specified
    if not output_dir:
        output_dir = input_dir

    # Create output directory if needed
    _make_missing_directory(output_dir, verbose, pretend_run, exit_on_failure)

    # Find AAX files
    aax_files = _find_aax_files(input_dir, recursive)
    if not aax_files:
        logger.log_warning(f"No AAX/AA files found in: {input_dir}")
        return True
    logger.log_info(f"Found {len(aax_files)} AAX/AA files to decrypt")

    # Decrypt files
    return decrypt_aax_files_to_m4a(
        input_files = aax_files,
        output_dir = output_dir,
        activation_bytes = activation_bytes,
        authcode_file = authcode_file,
        overwrite = overwrite,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Decrypt a directory of AAX files or a single one, by what the input path is; False, with
# an error, when it is neither
def decrypt_aax_path(
    input_path,
    output_path = None,
    activation_bytes = None,
    authcode_file = None,
    recursive = False,
    overwrite = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if paths.is_path_directory(input_path):
        return decrypt_aax_directory(
            input_dir = input_path,
            output_dir = output_path,
            activation_bytes = activation_bytes,
            authcode_file = authcode_file,
            recursive = recursive,
            overwrite = overwrite,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if paths.is_path_file(input_path):
        return decrypt_aax_to_m4a(
            input_file = input_path,
            output_file = output_path,
            activation_bytes = activation_bytes,
            authcode_file = authcode_file,
            overwrite = overwrite,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    logger.log_error(f"Input is not a file or directory: {input_path}")
    return False
