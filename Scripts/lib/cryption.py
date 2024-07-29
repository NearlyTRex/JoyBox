# Imports
import os, os.path
import sys

# Local imports
import config
import command
import programs
import system
import hashing

# Determine if file is encrypted
def IsFileEncrypted(source_file):
    return source_file.endswith(config.encrypted_file_extension)

# Get encrypted filename
def GetEncryptedFilename(source_file):
    output_dir = system.GetFilenameDirectory(source_file)
    output_name = hashing.CalculateStringMD5(system.GetFilenameFile(source_file)) + config.encrypted_file_extension
    return os.path.join(output_dir, output_name)

# Get embedded filename
def GetEmbeddedFilename(
    source_file,
    passphrase,
    verbose = False,
    exit_on_failure = False):

    # Get tool
    gpg_tool = None
    if programs.IsToolInstalled("Gpg"):
        gpg_tool = programs.GetToolProgram("Gpg")
    if not gpg_tool:
        system.LogError("Gpg was not found")
        return None

    # Get info command
    info_cmd = [
        gpg_tool,
        "--list-packets",
        "--passphrase", passphrase,
        "--quiet",
        "--batch",
        source_file
    ]

    # Run info command
    info_output = command.RunOutputCommand(
        cmd = info_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get embedded name
    if isinstance(info_output, bytes):
        info_output = info_output.decode()
    for possible_name in system.FindQuotedSubstrings(info_output):
        return possible_name
    return None

# Get real file path
def GetRealFilePath(
    source_file,
    passphrase,
    verbose = False,
    exit_on_failure = False):
    real_dir = system.GetFilenameDirectory(source_file)
    real_name = GetEmbeddedFilename(
        source_file = source_file,
        passphrase = passphrase,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if real_name:
        return os.path.join(real_dir, real_name)
    return None

# Get real file paths
def GetRealFilePaths(
    source_files,
    passphrase,
    verbose = False,
    exit_on_failure = False):
    real_paths = []
    if isinstance(source_files, list):
        for source_file in source_files:
            real_path = GetRealFilePath(
                source_file = source_file,
                passphrase = passphrase,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if real_path:
                real_paths.append(real_path)
    return real_paths

# Encrypt file
def EncryptFile(
    source_file,
    passphrase,
    output_file = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source file
    if not system.IsPathValid(source_file):
        return False
    if IsFileEncrypted(source_file):
        return True

    # Check output file
    if not output_file:
        output_file = GetEncryptedFilename(source_file)
    if not system.IsPathValid(output_file):
        return False
    if system.DoesPathExist(output_file):
        return True

    # Get tool
    gpg_tool = None
    if programs.IsToolInstalled("Gpg"):
        gpg_tool = programs.GetToolProgram("Gpg")
    if not gpg_tool:
        system.LogError("Gpg was not found")
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
        source_file
    ]

    # Run encrypt command
    code = command.RunBlockingCommand(
        cmd = encrypt_cmd,
        options = command.CommandOptions(
            blocking_processes = [gpg_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Unable to encrypt file '%s'" % source_file)
        return False

    # Delete original
    if delete_original and os.path.exists(output_file):
        system.RemoveFile(source_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)

# Decrypt file
def DecryptFile(
    source_file,
    passphrase,
    output_file = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source file
    if not system.IsPathValid(source_file):
        return False
    if not IsFileEncrypted(source_file):
        return True

    # Check output file
    if not output_file:
        output_file = GetRealFilePath(
            source_file = source_file,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    if not system.IsPathValid(output_file):
        return False
    if system.DoesPathExist(output_file):
        return True

    # Get tool
    gpg_tool = None
    if programs.IsToolInstalled("Gpg"):
        gpg_tool = programs.GetToolProgram("Gpg")
    if not gpg_tool:
        system.LogError("Gpg was not found")
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
        source_file
    ]

    # Run decrypt command
    code = command.RunBlockingCommand(
        cmd = decrypt_cmd,
        options = command.CommandOptions(
            blocking_processes = [gpg_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Unable to decrypt file '%s'" % source_file)
        return False

    # Delete original
    if delete_original and os.path.exists(output_file):
        system.RemoveFile(source_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)
