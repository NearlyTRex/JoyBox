# Imports
import os, os.path
import sys

# Local imports
import config
import command
import programs
import system

# Get encrypted filename
def GetEncryptedFilename(source_file):
    if source_file.endswith(".gpg"):
        return source_file
    return source_file + ".gpg"

# Get decrypted filename
def GetDecryptedFilename(source_file):
    if not source_file.endswith(".gpg"):
        return source_file
    return source_file[:-len(".gpg")]

# Encrypt file
def EncryptFile(source_file, output_file, passphrase, delete_original = False, verbose = False, exit_on_failure = False):

    # Ignore already encrypted
    if os.path.exists(output_file):
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
        "--quiet",
        "--batch",
        source_file
    ]

    # Run encrypt command
    code = command.RunBlockingCommand(
        cmd = encrypt_cmd,
        options = command.CommandOptions(
            blocking_processes = [gpg_tool]),
        verbose = verbose,
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
def DecryptFile(source_file, output_file, passphrase, delete_original = False, verbose = False, exit_on_failure = False):

    # Ignore already decrypted
    if os.path.exists(output_file):
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
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.LogError("Unable to decrypt file '%s'" % source_file)
        return False

    # Delete original
    if delete_original and os.path.exists(output_file):
        system.RemoveFile(source_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)
