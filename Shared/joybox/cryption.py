# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import fileops
from joybox import filebulk
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import text
from joybox import validation
from joybox import logger
from joybox import settings
from joybox import paths
from joybox import hashutil

# Determine if file is encrypted
def is_file_encrypted(src):
    for ext in config.EncryptedFileType.cvalues():
        if src.endswith(ext):
            return True
    return False

# Determine if passphrase is valid
def is_passphrase_valid(passphrase):
    return isinstance(passphrase, str) and len(passphrase) > 0

# The MD5 of the name plus the .enc extension; already-encrypted names come back unchanged
def generate_encrypted_filename(src):
    if is_file_encrypted(src):
        return src
    return hashutil.calculate_string_md5(src) + config.EncryptedFileType.ENC.cval()

# The source path with its file name swapped for the hashed .enc name, in the same directory
def generate_encrypted_path(source_path):
    output_dir = paths.get_filename_directory(source_path)
    output_name = generate_encrypted_filename(paths.get_filename_file(source_path))
    return paths.join_paths(output_dir, output_name)

# The original name gpg stored inside an encrypted file, read from its packet listing
# even in pretend mode; None when gpg is missing or no name is found
def get_embedded_filename(
    src,
    passphrase,
    verbose = False,
    exit_on_failure = False):

    # Check passphrase
    validation.assert_is_non_empty_string(passphrase, "passphrase")

    # Get tool
    gpg_tool = programs.find_tool_program("Gpg")
    if not gpg_tool:
        return None

    # Get info command
    info_cmd = [
        gpg_tool,
        "--list-packets",
        "--passphrase-fd", "0",
        "--quiet",
        "--batch",
        src
    ]

    # Run info command (always run, even in pretend mode - this is read-only)
    info_output = command.run_output_command(
        cmd = info_cmd,
        options = commandbase.create_command_options(
            stdin_input = passphrase),
        verbose = verbose,
        pretend_run = False,
        exit_on_failure = exit_on_failure)

    # Get embedded name
    if isinstance(info_output, bytes):
        info_output = info_output.decode()
    for possible_name in text.find_enclosed_substrings(info_output, "\"", "\""):
        return text.clean_rich_text(possible_name)
    return None

# Get the info of an encrypted file from its decrypted copy: the name it embeds, its hash when
# given a hasher, its size and the encrypted file's modification time
def get_decrypted_file_info(src, decrypted_file, embedded_filename, hasher, chunksize, verbose = False, pretend_run = False, exit_on_failure = False):
    file_info = {"filename": embedded_filename}
    if callable(hasher):
        file_info["hash"] = hasher(
            src = decrypted_file,
            chunksize = chunksize,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    file_info["size"] = paths.get_file_size(decrypted_file) if paths.does_path_exist(decrypted_file) else 0
    file_info["mtime"] = paths.get_file_mod_time(src)
    return file_info

# Decrypt into a temporary directory to read the embedded name, hash, size and mtime;
# None when the name can't be read or decryption fails
def get_embedded_file_info(
    src,
    passphrase,
    hasher,
    chunksize = config.HASH_CHUNK_SIZE,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get embedded filename
    embedded_filename = get_embedded_filename(
        src = src,
        passphrase = passphrase,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not embedded_filename:
        return None

    # Decrypt into a temporary directory and read the file decrypted
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return None
        tmp_file = paths.join_paths(tmp_dir, embedded_filename)
        success = decrypt_file(
            src = src,
            passphrase = passphrase,
            output_file = tmp_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None
        return get_decrypted_file_info(src, tmp_file, embedded_filename, hasher, chunksize, verbose, pretend_run, exit_on_failure)

# Where the decrypted copy lands: the embedded name beside the source, or the source itself
# when it isn't encrypted; None when the embedded name can't be read
def get_real_file_path(
    src,
    passphrase,
    verbose = False,
    exit_on_failure = False):
    if not is_file_encrypted(src):
        return src
    real_dir = paths.get_filename_directory(src)
    real_name = get_embedded_filename(
        src = src,
        passphrase = passphrase,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if real_name:
        return paths.join_paths(real_dir, real_name)
    return None

# The decrypted-copy paths for a list of files, skipping unreadable ones; empty for a non-list
def get_real_file_paths(
    src,
    passphrase,
    verbose = False,
    exit_on_failure = False):
    real_paths = []
    if isinstance(src, list):
        for source_file in src:
            real_path = get_real_file_path(
                src = source_file,
                passphrase = passphrase,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if real_path:
                real_paths.append(real_path)
    return real_paths

# Copy a file that needs no gpg run, keeping an existing destination
def _copy_unchanged(src, output_file, verbose, pretend_run, exit_on_failure):
    return filebulk.smart_copy(
        src = src,
        dest = output_file,
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run a gpg command reading the passphrase from stdin; True when it exits 0
def _run_gpg_command(gpg_cmd, passphrase, verbose, pretend_run, exit_on_failure):
    code = command.run_returncode_command(
        cmd = gpg_cmd,
        options = commandbase.create_command_options(
            blocking_processes = [gpg_cmd[0]],
            stdin_input = passphrase),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# After a gpg run: in a pretend run log what would happen and succeed, otherwise delete the
# original when asked once the output exists; whether the output exists
def _finish_gpg_output(src, output_file, action, delete_original, verbose, pretend_run, exit_on_failure):

    # In pretend mode, assume success
    if pretend_run:
        logger.log_info("Would %s '%s' -> '%s'" % (action, src, output_file))
        return True

    # Delete original
    if delete_original and os.path.exists(output_file):
        fileops.remove_file(
            src = src,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)

# The gpg command encrypting src with AES256 to the output, keeping its file name inside
def _build_encrypt_command(gpg_tool, src, output_file):
    return [
        gpg_tool,
        "--symmetric",
        "--cipher-algo", "AES256",
        "--passphrase-fd", "0",
        "--compress-algo", "none",
        "--set-filename", paths.get_filename_file(src),
        "--quiet",
        "--batch",
        "--output", output_file,
        src
    ]

# The gpg command decrypting src to the output
def _build_decrypt_command(gpg_tool, src, output_file):
    return [
        gpg_tool,
        "--output", output_file,
        "--passphrase-fd", "0",
        "--compress-algo", "none",
        "--quiet",
        "--batch",
        "--decrypt",
        src
    ]

# Encrypt with gpg AES256 under the passphrase, to the hashed .enc path unless given one;
# copies already-encrypted files, keeps an existing output, and can delete the original
def encrypt_file(
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
        output_file = generate_encrypted_path(src)
    if not paths.is_path_valid(output_file):
        return False
    if paths.does_path_exist(output_file):
        return True

    # Plain copy if already encrypted
    if is_file_encrypted(src):
        return _copy_unchanged(src, output_file, verbose, pretend_run, exit_on_failure)

    # Get tool
    gpg_tool = programs.find_tool_program("Gpg")
    if not gpg_tool:
        return False

    # Run encrypt command
    if not _run_gpg_command(_build_encrypt_command(gpg_tool, src, output_file), passphrase, verbose, pretend_run, exit_on_failure):
        logger.log_error("Unable to encrypt file '%s'" % src)
        return False
    return _finish_gpg_output(src, output_file, "encrypt", delete_original, verbose, pretend_run, exit_on_failure)

# Decrypt with gpg to the embedded name unless given an output; copies unencrypted files,
# keeps an existing output, and can delete the original
def decrypt_file(
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
        output_file = get_real_file_path(src, passphrase, verbose = verbose, exit_on_failure = exit_on_failure)
    if not paths.is_path_valid(output_file):
        return False
    if paths.does_path_exist(output_file):
        return True

    # Plain copy if already decrypted
    if not is_file_encrypted(src):
        return _copy_unchanged(src, output_file, verbose, pretend_run, exit_on_failure)

    # Get tool
    gpg_tool = programs.find_tool_program("Gpg")
    if not gpg_tool:
        return False

    # Run decrypt command
    if not _run_gpg_command(_build_decrypt_command(gpg_tool, src, output_file), passphrase, verbose, pretend_run, exit_on_failure):
        logger.log_error("Unable to decrypt file '%s'" % src)
        return False
    return _finish_gpg_output(src, output_file, "decrypt", delete_original, verbose, pretend_run, exit_on_failure)

# Encrypt every file under the source to its hashed .enc path; returns the outputs that succeeded
def encrypt_files(
    src,
    passphrase,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output_files = []
    for file in paths.build_file_list(src):
        output_file = generate_encrypted_path(file)
        success = encrypt_file(
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

# Decrypt every file under the source to its embedded name; returns the outputs that succeeded
def decrypt_files(
    src,
    passphrase,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output_files = []
    for file in paths.build_file_list(src):
        output_file = get_real_file_path(
            src = file,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not output_file:
            logger.log_error("Unable to read the embedded name of '%s'" % file)
            continue
        success = decrypt_file(
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

###########################################################
# Transfers
###########################################################

# Cryption types a transfer understands
CRYPTION_TYPES = (
    config.CryptionType.NONE,
    config.CryptionType.ENCRYPT,
    config.CryptionType.DECRYPT,
)

# The function that carries out an encrypt or decrypt
def get_cryption_function(cryption_type):
    if cryption_type == config.CryptionType.ENCRYPT:
        return encrypt_file
    return decrypt_file

# Encrypt a batch of files into a staging directory, each under its destination's encrypted
# path, returning the destinations staged and those that failed
def stage_encrypted_batch(batch, src_root, staging, passphrase, verbose = False, pretend_run = False, exit_on_failure = False):
    staged, failed = [], []
    for action in batch:
        src_rel = action.get("src", "")
        dest_rel = action.get("dest", src_rel)
        dest_dir_rel = paths.get_filename_directory(dest_rel)
        staged_dir = paths.join_paths(staging, dest_dir_rel) if dest_dir_rel else staging
        fileops.make_directory(src = staged_dir)
        if encrypt_file(
            src = paths.join_paths(src_root, src_rel),
            passphrase = passphrase,
            output_file = paths.join_paths(staged_dir, generate_encrypted_filename(paths.get_filename_file(dest_rel))),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            staged.append(dest_rel)
        else:
            logger.log_error("Failed to encrypt: %s" % dest_rel)
            failed.append(dest_rel)
    return staged, failed

# The passphrase the type names from the protection settings; quits when it is not set
def get_configured_passphrase(passphrase_type):
    passphrase = None
    if passphrase_type == config.PassphraseType.GENERAL:
        passphrase = settings.get_value("UserData.Protection", "general_passphrase")
    elif passphrase_type == config.PassphraseType.LOCKER:
        passphrase = settings.get_value("UserData.Protection", "locker_passphrase")
    if not passphrase:
        logger.log_error("No passphrase set", quit_program = True)
    return passphrase

# "Encrypt" or "Decrypt" for the chosen direction, encrypting when both are chosen; None for neither
def get_crypt_action(encrypt = False, decrypt = False):
    if encrypt:
        return "Encrypt"
    return "Decrypt" if decrypt else None

# Encrypt, or else decrypt, every file under the source in place with gpg's default naming;
# False, logged, when neither is asked for
def crypt_files_in_place(
    src,
    passphrase,
    encrypt = False,
    decrypt = False,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if encrypt:
        crypt_function = encrypt_file
    elif decrypt:
        crypt_function = decrypt_file
    else:
        logger.log_error("Give -e to encrypt or -d to decrypt")
        return False
    for file in paths.build_file_list(src):
        crypt_function(
            src = file,
            passphrase = passphrase,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True
