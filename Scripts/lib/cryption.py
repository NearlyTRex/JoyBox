# Imports
import os, os.path
import sys

# Local imports
import config
import command
import programs
import system
import hashing

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
    if source_file.endswith(".gpg"):
        return True

    # Check output file
    if not output_file:
        output_dir = system.GetFilenameDirectory(source_file)
        output_name = hashing.CalculateStringMD5(system.GetFilenameFile(source_file)) + ".gpg"
        output_file = os.path.join(output_dir, output_name)
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
    if not source_file.endswith(".gpg"):
        return True

    # Check output file
    if not output_file:
        output_dir = system.GetFilenameDirectory(source_file)
        output_name = GetEmbeddedFilename(
            source_file = source_file,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if output_name:
            output_file = os.path.join(output_dir, output_name)
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
