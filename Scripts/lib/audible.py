# Imports
import os
import sys
import json
import re
import subprocess

# Local imports
import config
import system
import validation
import logger
import paths
import environment
import fileops
import command
import programs
import serialization
import ini

# Extract activation bytes from text (finds 8 hex character sequence)
def ExtractActivationBytes(text):
    if not text:
        return None
    match = re.search(r'\b([0-9a-fA-F]{8})\b', text)
    if match:
        return match.group(1)
    return None

# Get activation bytes
def GetActivationBytes(authcode_file = None, verbose = False, exit_on_failure = False):

    # Check ini file first
    authcode = ini.GetIniValue("UserData.Audible", "audible_activation_bytes")
    if authcode:
        extracted = ExtractActivationBytes(authcode)
        if extracted:
            return extracted

    # Check authcode file
    if authcode_file and paths.is_path_file(authcode_file):
        authcode = serialization.read_text_file(
            src = authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if authcode:
            extracted = ExtractActivationBytes(authcode)
            if extracted:
                return extracted

    # Check environment variable
    authcode = os.environ.get("AUDIBLE_ACTIVATION_BYTES")
    if authcode:
        extracted = ExtractActivationBytes(authcode)
        if extracted:
            return extracted

    # Check default location
    default_authcode_file = paths.join_paths(environment.get_home_directory(), ".audible_authcode")
    if paths.is_path_file(default_authcode_file):
        authcode = serialization.read_text_file(
            src = default_authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if authcode:
            extracted = ExtractActivationBytes(authcode)
            if extracted:
                return extracted
    return None

# Decrypt AAX file to M4A using FFMpeg
def DecryptAAXToM4A(
    input_file,
    output_file = None,
    activation_bytes = None,
    authcode_file = None,
    overwrite = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate input file
    validation.assert_is_valid_path(input_file, "input_file")
    if not paths.is_path_file(input_file):
        logger.log_error(f"Input file does not exist: {input_file}")
        if exit_on_failure:
            system.quit_program()
        return False

    # Check file extension
    input_ext = paths.get_filename_extension(input_file).lower()
    if input_ext not in [".aax", ".aa"]:
        logger.log_error(f"Input file must be .aax or .aa format: {input_file}")
        if exit_on_failure:
            system.quit_program()
        return False

    # Determine output file
    if not output_file:
        output_file = paths.change_filename_extension(input_file, ".m4a")

    # Check if output already exists
    if paths.is_path_file(output_file) and not overwrite:
        logger.log_warning(f"Output file already exists, skipping: {output_file}")
        return True

    # Get activation bytes
    if not activation_bytes:
        activation_bytes = GetActivationBytes(
            authcode_file = authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    if not activation_bytes:
        logger.log_error("Activation bytes not provided or found in environment")
        if exit_on_failure:
            system.quit_program()
        return False

    # Validate activation bytes format (should be 8 hex characters)
    if len(activation_bytes) != 8 or not all(c in '0123456789abcdefABCDEF' for c in activation_bytes):
        logger.log_error(f"Invalid activation bytes format. Expected 8 hex characters, got: {activation_bytes}")
        if exit_on_failure:
            system.quit_program()
        return False

    # Check for FFMpeg
    ffmpeg_tool = None
    if programs.IsToolInstalled("FFMpeg"):
        ffmpeg_tool = programs.GetToolProgram("FFMpeg")
    if not ffmpeg_tool:
        logger.log_error("FFMpeg was not found")
        if exit_on_failure:
            system.quit_program()
        return False

    # Log operation
    logger.log_info(f"Decrypting AAX file: {input_file}")
    logger.log_info(f"Output file: {output_file}")

    # Create output directory if needed
    output_dir = paths.get_filename_directory(output_file)
    if output_dir and not paths.is_path_directory(output_dir):
        fileops.make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Build FFMpeg command
    # -activation_bytes: The Audible activation bytes for decryption
    # -i: Input file
    # -c copy: Copy streams without re-encoding (preserves quality and chapters)
    # -vn: Disable video (removes cover art stream if present, but keeps audio)
    ffmpeg_cmd = [
        ffmpeg_tool,
        "-activation_bytes", activation_bytes,
        "-i", input_file,
        "-c", "copy",
        "-y" if overwrite else "-n",
        output_file
    ]

    # Run FFMpeg
    if not pretend_run:
        code = command.RunReturncodeCommand(
            cmd = ffmpeg_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            logger.log_error(f"FFMpeg decryption failed with code {code}")
            if exit_on_failure:
                system.quit_program()
            return False
    logger.log_info(f"Successfully decrypted: {output_file}")
    return True

# Decrypt multiple AAX files to M4A
def DecryptAAXFilesToM4A(
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
        logger.log_error("No input files provided")
        if exit_on_failure:
            system.quit_program()
        return False

    # Get activation bytes once for all files
    if not activation_bytes:
        activation_bytes = GetActivationBytes(
            authcode_file = authcode_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    if not activation_bytes:
        logger.log_error("Activation bytes not provided")
        if exit_on_failure:
            system.quit_program()
        return False

    # Process each file
    success_count = 0
    fail_count = 0
    for input_file in input_files:

        # Determine output file
        output_file = None
        if output_dir:
            filename = paths.get_filename_file(input_file)
            filename = paths.change_filename_extension(filename, ".m4a")
            output_file = paths.join_paths(output_dir, filename)

        # Decrypt file
        success = DecryptAAXToM4A(
            input_file = input_file,
            output_file = output_file,
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
                system.quit_program()

    # Log summary
    logger.log_info(f"Decryption complete: {success_count} succeeded, {fail_count} failed")
    return fail_count == 0

# Decrypt all AAX files in a directory
def DecryptAAXDirectory(
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
        logger.log_error(f"Input directory does not exist: {input_dir}")
        if exit_on_failure:
            system.quit_program()
        return False

    # Use input directory as output if not specified
    if not output_dir:
        output_dir = input_dir

    # Create output directory if needed
    if not paths.is_path_directory(output_dir):
        fileops.make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Find AAX files
    aax_files = []
    if recursive:
        for root, dirs, files in os.walk(input_dir):
            for filename in files:
                if filename.lower().endswith((".aax", ".aa")):
                    aax_files.append(paths.join_paths(root, filename))
    else:
        for item in paths.get_directory_contents(input_dir):
            if item.lower().endswith((".aax", ".aa")):
                aax_files.append(paths.join_paths(input_dir, item))
    if not aax_files:
        logger.log_warning(f"No AAX/AA files found in: {input_dir}")
        return True
    logger.log_info(f"Found {len(aax_files)} AAX/AA files to decrypt")

    # Decrypt files
    return DecryptAAXFilesToM4A(
        input_files = aax_files,
        output_dir = output_dir,
        activation_bytes = activation_bytes,
        authcode_file = authcode_file,
        overwrite = overwrite,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
