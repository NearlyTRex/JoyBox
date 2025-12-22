# Imports
import os, os.path
import sys

# Local imports
import config
import fileops
import command
import programs
import strings
import system
import text
import validation
import logger
import paths
import hashing

# Determine if file is encrypted
def IsFileEncrypted(src):
    for ext in config.EncryptedFileType.cvalues():
        if src.endswith(ext):
            return True
    return False

# Determine if passphrase is valid
def IsPassphraseValid(passphrase):
    return isinstance(passphrase, str) and len(passphrase) > 0

# Generate encrypted filename
def GenerateEncryptedFilename(src):
    if IsFileEncrypted(src):
        return src
    return hashing.CalculateStringMD5(src) + config.EncryptedFileType.ENC.cval()

# Generate encrypted path
def GenerateEncryptedPath(source_path):
    output_dir = paths.get_filename_directory(source_path)
    output_name = GenerateEncryptedFilename(paths.get_filename_file(source_path))
    return paths.join_paths(output_dir, output_name)

# Get embedded filename
def GetEmbeddedFilename(
    src,
    passphrase,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check passphrase
    validation.assert_is_non_empty_string(passphrase, "passphrase")

    # Get tool
    gpg_tool = None
    if programs.IsToolInstalled("Gpg"):
        gpg_tool = programs.GetToolProgram("Gpg")
    if not gpg_tool:
        logger.log_error("Gpg was not found")
        return None

    # Get info command
    info_cmd = [
        gpg_tool,
        "--list-packets",
        "--passphrase", passphrase,
        "--quiet",
        "--batch",
        src
    ]

    # Run info command
    info_output = command.RunOutputCommand(
        cmd = info_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get embedded name
    if isinstance(info_output, bytes):
        info_output = info_output.decode()
    for possible_name in strings.find_enclosed_substrings(info_output, "\"", "\""):
        return text.clean_rich_text(possible_name)
    return None

# Get embedded file info
def GetEmbeddedFileInfo(
    src,
    passphrase,
    hasher,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get embedded filename
    embedded_filename = GetEmbeddedFilename(
        src = src,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not embedded_filename:
        return None

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return None

    # Get temporary file
    tmp_file = paths.join_paths(tmp_dir_result, embedded_filename)

    # Decrypt file
    success = DecryptFile(
        src = src,
        passphrase = passphrase,
        output_file = tmp_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return None

    # Get file info
    file_info = {}
    file_info["filename"] = embedded_filename
    if callable(hasher):
        file_info["hash"] = hasher(
            src = tmp_file,
            chunksize = chunksize,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    file_info["size"] = os.path.getsize(tmp_file)
    file_info["mtime"] = int(os.path.getmtime(src))

    # Clean up
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return file info
    return file_info

# Get real file path
def GetRealFilePath(
    src,
    passphrase,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not IsFileEncrypted(src):
        return src
    real_dir = paths.get_filename_directory(src)
    real_name = GetEmbeddedFilename(
        src = src,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if real_name:
        return paths.join_paths(real_dir, real_name)
    return None

# Get real file paths
def GetRealFilePaths(
    src,
    passphrase,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    real_paths = []
    if isinstance(src, list):
        for source_file in src:
            real_path = GetRealFilePath(
                src = source_file,
                passphrase = passphrase,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if real_path:
                real_paths.append(real_path)
    return real_paths

# Encrypt file
def EncryptFile(
    src,
    passphrase,
    output_file = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check passphrase
    validation.assert_is_non_empty_string(passphrase, "passphrase")

    # Check source file
    if not paths.is_path_valid(src):
        return False

    # Check output file
    if not output_file:
        output_file = GenerateEncryptedPath(src)
    if not paths.is_path_valid(output_file):
        return False
    if paths.does_path_exist(output_file):
        return True

    # Plain copy if already encrypted
    if IsFileEncrypted(src):
        success = fileops.smart_copy(
            src = src,
            dest = output_file,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    # Get tool
    gpg_tool = None
    if programs.IsToolInstalled("Gpg"):
        gpg_tool = programs.GetToolProgram("Gpg")
    if not gpg_tool:
        logger.log_error("Gpg was not found")
        return False

    # Get encrypt command
    encrypt_cmd = [
        gpg_tool,
        "--symmetric",
        "--cipher-algo", "AES256",
        "--passphrase", passphrase,
        "--compress-algo", "none",
        "--quiet",
        "--batch",
        "--output", output_file,
        src
    ]

    # Run encrypt command
    code = command.RunReturncodeCommand(
        cmd = encrypt_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [gpg_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to encrypt file '%s'" % src)
        return False

    # Delete original
    if delete_original and os.path.exists(output_file):
        fileops.remove_file(
            src = src,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)

# Decrypt file
def DecryptFile(
    src,
    passphrase,
    output_file = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check passphrase
    validation.assert_is_non_empty_string(passphrase, "passphrase")

    # Check source file
    if not paths.is_path_valid(src):
        return False

    # Check output file
    if not output_file:
        output_file = GetRealFilePath(
            src = src,
            passphrase = passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not paths.is_path_valid(output_file):
        return False
    if paths.does_path_exist(output_file):
        return True

    # Plain copy if already decrypted
    if not IsFileEncrypted(src):
        success = fileops.smart_copy(
            src = src,
            dest = output_file,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    # Get tool
    gpg_tool = None
    if programs.IsToolInstalled("Gpg"):
        gpg_tool = programs.GetToolProgram("Gpg")
    if not gpg_tool:
        logger.log_error("Gpg was not found")
        return False

    # Get decrypt command
    decrypt_cmd = [
        gpg_tool,
        "--output", output_file,
        "--passphrase", passphrase,
        "--compress-algo", "none",
        "--quiet",
        "--batch",
        "--decrypt",
        src
    ]

    # Run decrypt command
    code = command.RunReturncodeCommand(
        cmd = decrypt_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [gpg_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to decrypt file '%s'" % src)
        return False

    # Delete original
    if delete_original and os.path.exists(output_file):
        fileops.remove_file(
            src = src,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)

# Encrypt files
def EncryptFiles(
    src,
    passphrase,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output_files = []
    for file in paths.build_file_list(src):
        output_file = GenerateEncryptedPath(file)
        success = EncryptFile(
            src = file,
            output_file = output_file,
            passphrase = passphrase,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if success:
            output_files.append(output_file)
    return output_files

# Decrypt files
def DecryptFiles(
    src,
    passphrase,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output_files = []
    for file in paths.build_file_list(src):
        output_file = GetRealFilePath(
            src = file,
            passphrase = passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        success = DecryptFile(
            src = file,
            output_file = output_file,
            passphrase = passphrase,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if success:
            output_files.append(output_file)
    return output_files
