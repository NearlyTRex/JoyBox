# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import programs
import system
import environment
import iso
import chd

######################################################
# Sony PlayStation 3
######################################################

# Get decryption key
def GetPS3DecryptionKey(dkey_file):
    dkey_contents = ""
    if os.path.exists(dkey_file):
        with open(dkey_file, "r", encoding="utf-8") as f:
            dkey_contents = f.read().strip()
    return dkey_contents

# Encrypt ps3 iso
def EncryptPS3ISO(iso_file_dec, iso_file_enc, dkey_file, verbose = False, exit_on_failure = False):

    # Get decryption key
    decryption_key = GetPS3DecryptionKey(dkey_file)
    if len(decryption_key) == 0:
        if exit_on_failure:
            print("PS3 key file '%s' is invalid" % dkey_file)
            sys.exit(1)
        return False

    # Get encrypt command
    encrypt_cmd = [
        programs.GetToolProgram("PS3Dec"),
        "e",
        "key", decryption_key,
        iso_file_dec,
        iso_file_enc
    ]

    # Run encrypt command
    code = command.RunBlockingCommand(
        cmd = encrypt_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to encrypt ps3 iso '%s' to '%s'" % (iso_file_dec, iso_file_enc))
            sys.exit(1)
        return False

    # Check result
    return os.path.exists(iso_file_enc)

# Decrypt ps3 iso
def DecryptPS3ISO(iso_file_enc, iso_file_dec, dkey_file, verbose = False, exit_on_failure = False):

    # Get decryption key
    decryption_key = GetPS3DecryptionKey(dkey_file)
    if len(decryption_key) == 0:
        if exit_on_failure:
            print("PS3 key file '%s' is invalid" % dkey_file)
            sys.exit(1)
        return False

    # Get decrypt command
    decrypt_cmd = [
        programs.GetToolProgram("PS3Dec"),
        "d",
        "key", decryption_key,
        iso_file_enc,
        iso_file_dec
    ]

    # Run decrypt command
    code = command.RunBlockingCommand(
        cmd = decrypt_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to decrypt ps3 iso '%s' to '%s'" % (iso_file_enc, iso_file_dec))
            sys.exit(1)
        return False

    # Check result
    return os.path.exists(iso_file_dec)

# Extract ps3 iso
def ExtractPS3ISO(iso_file, dkey_file, extract_dir, delete_original = False, verbose = False, exit_on_failure = False):

    # Get file info
    iso_file_basename = system.GetFilenameBasename(iso_file)
    iso_file_directory = system.GetFilenameDirectory(iso_file)
    iso_file_enc = iso_file
    iso_file_dec = os.path.join(iso_file_directory, iso_file_basename + ".dec.iso")

    # Decrypt iso
    success = DecryptPS3ISO(
        iso_file_enc = iso_file_enc,
        iso_file_dec = iso_file_dec,
        dkey_file = dkey_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Extract decrypted iso
    success = iso.ExtractISO(
        iso_file = iso_file_dec,
        extract_dir = extract_dir,
        delete_original = delete_original,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check license file
    license_file = os.path.join(extract_dir, "PS3_GAME", "LICDIR", "LIC.DAT")
    if os.path.exists(license_file):
        if not system.IsFileCorrectlyHeadered(license_file, "PS3LICDA"):
            if exit_on_failure:
                print("Decryption failure, LIC.DAT '%s' has the wrong header (expected PS3LICDA)." % license_file)
                print("It seems likely that the decryption key file '%s' is not compatible with '%s'" % (dkey_file, iso_file_enc))
                sys.exit(1)
            return False

    # Check eboot file
    eboot_file = os.path.join(extract_dir, "PS3_GAME", "USRDIR", "EBOOT.BIN")
    if os.path.exists(eboot_file):
        if not system.IsFileCorrectlyHeadered(eboot_file, "SCE"):
            if exit_on_failure:
                print("Decryption failure, EBOOT.BIN '%s' has the wrong header (expected SCE)." % eboot_file)
                print("It seems likely that the decryption key file '%s' is not compatible with '%s'" % (dkey_file, iso_file_enc))
                sys.exit(1)
            return False

    # Clean up
    if delete_original:
        system.RemoveFile(iso_file_dec, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir)

# Verify ps3 chd
def VerifyPS3CHD(chd_file, verbose = False, exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get rom file info
    iso_tmp_dir = os.path.join(tmp_dir_result, "iso")
    raw_tmp_dir = os.path.join(tmp_dir_result, "raw")
    input_chd_file = chd_file
    input_chd_dir = system.GetFilenameDirectory(input_chd_file)
    input_chd_basename = system.GetFilenameBasename(input_chd_file)
    input_dkey_file = os.path.join(input_chd_dir, input_chd_basename + ".dkey")
    output_iso_bin_file = os.path.join(iso_tmp_dir, input_chd_basename + ".iso")
    output_iso_toc_file = os.path.join(iso_tmp_dir, input_chd_basename + ".toc")

    # Make directories
    system.MakeDirectory(iso_tmp_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(raw_tmp_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Extract chd
    success = chd.ExtractDiscCHD(
        chd_file = input_chd_file,
        binary_file = output_iso_bin_file,
        toc_file = output_iso_toc_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Extract ps3 iso
    success = ExtractPS3ISO(
        iso_file = output_iso_bin_file,
        dkey_file = input_dkey_file,
        extract_dir = raw_tmp_dir,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Should be verified now
    return True

# Extract psn pkg
def ExtractPSNPKG(pkg_file, extract_dir, delete_original = False, verbose = False, exit_on_failure = False):

    # Get extract command
    extract_cmd = [
        environment.GetPythonVirtualEnvInterpreter(),
        programs.GetToolProgram("PSNGetPkgInfo"),
        "--content", extract_dir,
        pkg_file
    ]

    # Run extract command
    try:
        command.RunExceptionCommand(
            cmd = extract_cmd,
            verbose = verbose)
    except:
        if exit_on_failure:
            print("Unable to extract psn pkg '%s' to '%s'" % (pkg_file, extract_dir))
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(pkg_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir)

######################################################
# Sony PlayStation Vita
######################################################

# Strip psv file
def StripPSV(unstripped_psv_file, stripped_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get strip command
    strip_cmd = [
        programs.GetToolProgram("PSVStrip"),
        "-psvstrip",
        unstripped_psv_file,
        stripped_psv_file
    ]

    # Run strip command
    code = command.RunBlockingCommand(
        cmd = strip_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to strip psv file '%s'" % unstripped_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(unstripped_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(stripped_psv_file)

# Unstrip psv file
def UnstripPSV(stripped_psv_file, stripped_psve_file, unstripped_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get unstrip command
    unstrip_cmd = [
        programs.GetToolProgram("PSVStrip"),
        "-applypsve",
        stripped_psv_file,
        unstripped_psv_file,
        stripped_psve_file
    ]

    # Run unstrip command
    code = command.RunBlockingCommand(
        cmd = unstrip_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to unstrip psv file '%s'" % stripped_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(stripped_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(unstripped_psv_file)

# Trim psv file
def TrimPSV(untrimmed_psv_file, trimmed_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get trim command
    trim_cmd = [
        environment.GetPythonVirtualEnvInterpreter(),
        programs.GetToolProgram("PSVTools"),
        "--trim",
        "-o", trimmed_psv_file,
        untrimmed_psv_file
    ]

    # Run trim command
    code = command.RunBlockingCommand(
        cmd = trim_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to trim psv file '%s'" % untrimmed_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(untrimmed_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(trimmed_psv_file)

# Untrim psv file
def UntrimPSV(trimmed_psv_file, untrimmed_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get untrim command
    untrim_cmd = [
        environment.GetPythonVirtualEnvInterpreter(),
        programs.GetToolProgram("PSVTools"),
        "--expand",
        "-o", untrimmed_psv_file,
        trimmed_psv_file
    ]

    # Run untrim command
    code = command.RunBlockingCommand(
        cmd = untrim_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to untrim psv file '%s'" % trimmed_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(trimmed_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(untrimmed_psv_file)

# Verify psv file
def VerifyPSV(psv_file, verbose = False, exit_on_failure = False):

    # Get verify command
    verify_cmd = [
        environment.GetPythonVirtualEnvInterpreter(),
        programs.GetToolProgram("PSVTools"),
        "--verify",
        psv_file
    ]

    # Run verify command
    code = command.RunBlockingCommand(
        cmd = verify_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            print("Unable to verify psv file '%s'" % psv_file)
            sys.exit(1)
        return False

    # Must be good
    return True

######################################################
# Sony PlayStation Network
######################################################

# Get psn pkg content id
def GetPSNPKGContentID(pkg_file):
    with open(pkg_file, 'rb') as f:
        f.seek(0x30)
        return f.read(0x24).decode("utf-8")
