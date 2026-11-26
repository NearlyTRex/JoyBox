# Nintendo DS roms: encrypting and decrypting them.

# Imports

# Local imports
from joybox import command
from joybox import commandbase
from joybox import programs

# Encrypt Nintendo DS rom
def encrypt_nds_rom(
    nds_file,
    generate_hash = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    encrypt_tool = programs.find_tool_program("NDecrypt")
    if not encrypt_tool:
        return False

    # Get encrypt command
    encrypt_cmd = [encrypt_tool]
    encrypt_cmd += ["e"]
    if generate_hash:
        encrypt_cmd += ["-h"]
    encrypt_cmd += [nds_file]

    # Run encrypt command
    code = command.run_returncode_command(
        cmd = encrypt_cmd,
        options = commandbase.create_command_options(
            blocking_processes = [encrypt_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Decrypt Nintendo DS rom
def decrypt_nds_rom(
    nds_file,
    generate_hash = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    decrypt_tool = programs.find_tool_program("NDecrypt")
    if not decrypt_tool:
        return False

    # Get decrypt command
    decrypt_cmd = [decrypt_tool]
    decrypt_cmd += ["d"]
    if generate_hash:
        decrypt_cmd += ["-h"]
    decrypt_cmd += [nds_file]

    # Run decrypt command
    code = command.run_returncode_command(
        cmd = decrypt_cmd,
        options = commandbase.create_command_options(
            blocking_processes = [decrypt_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

######################################################
