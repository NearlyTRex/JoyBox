# Imports
import os
import os.path
import sys

# Local imports
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

    # Get tool
    encrypt_tool = None
    if programs.IsToolInstalled("PS3Dec"):
        encrypt_tool = programs.GetToolProgram("PS3Dec")
    if not encrypt_tool:
        system.LogError("PS3Dec was not found")
        return False

    # Get encryption key
    encryption_key = GetPS3DecryptionKey(dkey_file)
    if len(encryption_key) == 0:
        if exit_on_failure:
            system.LogError("PS3 key file '%s' is invalid" % dkey_file)
            sys.exit(1)
        return False

    # Get encrypt command
    encrypt_cmd = [
        encrypt_tool,
        "e",
        "key", encryption_key,
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
            system.LogError("Unable to encrypt ps3 iso '%s' to '%s'" % (iso_file_dec, iso_file_enc))
            sys.exit(1)
        return False

    # Check result
    return os.path.exists(iso_file_enc)

# Decrypt ps3 iso
def DecryptPS3ISO(iso_file_enc, iso_file_dec, dkey_file, verbose = False, exit_on_failure = False):

    # Get tool
    decrypt_tool = None
    if programs.IsToolInstalled("PS3Dec"):
        decrypt_tool = programs.GetToolProgram("PS3Dec")
    if not decrypt_tool:
        system.LogError("PS3Dec was not found")
        return False

    # Get decryption key
    decryption_key = GetPS3DecryptionKey(dkey_file)
    if len(decryption_key) == 0:
        if exit_on_failure:
            system.LogError("PS3 key file '%s' is invalid" % dkey_file)
            sys.exit(1)
        return False

    # Get decrypt command
    decrypt_cmd = [
        decrypt_tool,
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
            system.LogError("Unable to decrypt ps3 iso '%s' to '%s'" % (iso_file_enc, iso_file_dec))
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
                system.LogError("Decryption failure, LIC.DAT '%s' has the wrong header (expected PS3LICDA)." % license_file)
                system.LogError("It seems likely that the decryption key file '%s' is not compatible with '%s'" % (dkey_file, iso_file_enc))
                sys.exit(1)
            return False

    # Check eboot file
    eboot_file = os.path.join(extract_dir, "PS3_GAME", "USRDIR", "EBOOT.BIN")
    if os.path.exists(eboot_file):
        if not system.IsFileCorrectlyHeadered(eboot_file, "SCE"):
            if exit_on_failure:
                system.LogError("Decryption failure, EBOOT.BIN '%s' has the wrong header (expected SCE)." % eboot_file)
                system.LogError("It seems likely that the decryption key file '%s' is not compatible with '%s'" % (dkey_file, iso_file_enc))
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

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    extract_script = None
    if programs.IsToolInstalled("PSNGetPkgInfo"):
        extract_script = programs.GetToolProgram("PSNGetPkgInfo")
    if not extract_script:
        system.LogError("PSNGetPkgInfo was not found")
        return False

    # Get extract command
    extract_cmd = [
        python_tool,
        extract_script,
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
            system.LogError("Unable to extract psn pkg '%s' to '%s'" % (pkg_file, extract_dir))
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
def StripPSV(src_psv_file, dest_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    strip_tool = None
    if programs.IsToolInstalled("PSVStrip"):
        strip_tool = programs.GetToolProgram("PSVStrip")
    if not strip_tool:
        system.LogError("PSVStrip was not found")
        return False

    # Get strip command
    strip_cmd = [
        strip_tool,
        "-psvstrip",
        src_psv_file,
        dest_psv_file
    ]

    # Run strip command
    code = command.RunBlockingCommand(
        cmd = strip_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            system.LogError("Unable to strip psv file '%s'" % src_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(src_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_psv_file)

# Unstrip psv file
def UnstripPSV(src_psv_file, src_psve_file, dest_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    unstrip_tool = None
    if programs.IsToolInstalled("PSVStrip"):
        unstrip_tool = programs.GetToolProgram("PSVStrip")
    if not unstrip_tool:
        system.LogError("PSVStrip was not found")
        return False

    # Get unstrip command
    unstrip_cmd = [
        unstrip_tool,
        "-applypsve",
        src_psv_file,
        dest_psv_file,
        src_psve_file
    ]

    # Run unstrip command
    code = command.RunBlockingCommand(
        cmd = unstrip_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            system.LogError("Unable to unstrip psv file '%s'" % src_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(src_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_psv_file)

# Trim psv file
def TrimPSV(src_psv_file, dest_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    trim_script = None
    if programs.IsToolInstalled("PSVTools"):
        trim_script = programs.GetToolProgram("PSVTools")
    if not trim_script:
        system.LogError("PSVTools was not found")
        return False

    # Get trim command
    trim_cmd = [
        python_tool,
        trim_script,
        "--trim",
        "-o", dest_psv_file,
        src_psv_file
    ]

    # Run trim command
    code = command.RunBlockingCommand(
        cmd = trim_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            system.LogError("Unable to trim psv file '%s'" % src_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(src_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_psv_file)

# Untrim psv file
def UntrimPSV(src_psv_file, dest_psv_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    untrim_script = None
    if programs.IsToolInstalled("PSVTools"):
        untrim_script = programs.GetToolProgram("PSVTools")
    if not untrim_script:
        system.LogError("PSVTools was not found")
        return False

    # Get untrim command
    untrim_cmd = [
        python_tool,
        untrim_script,
        "--expand",
        "-o", dest_psv_file,
        src_psv_file
    ]

    # Run untrim command
    code = command.RunBlockingCommand(
        cmd = untrim_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        if exit_on_failure:
            system.LogError("Unable to untrim psv file '%s'" % src_psv_file)
            sys.exit(1)
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(src_psv_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_psv_file)

# Verify psv file
def VerifyPSV(psv_file, verbose = False, exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    verify_script = None
    if programs.IsToolInstalled("PSVTools"):
        verify_script = programs.GetToolProgram("PSVTools")
    if not verify_script:
        system.LogError("PSVTools was not found")
        return False

    # Get verify command
    verify_cmd = [
        python_tool,
        verify_script,
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
            system.LogError("Unable to verify psv file '%s'" % psv_file)
            sys.exit(1)
        return False

    # Must be good
    return True

######################################################
# Sony PlayStation Network
######################################################

# Get psn package content id
def GetPSNPackageContentID(pkg_file):
    try:
        with open(pkg_file, "rb") as f:
            f.seek(0x30)
            return f.read(0x24).decode("utf-8")
    except:
        pass
    return None

# Get psn work.bin content id
def GetPSNWorkBinContentID(workbin_file):
    try:
        with open(workbin_file, "rb") as f:
            f.seek(0x10)
            return f.read(0x24).decode("utf-8")
    except:
        pass
    return None

# Get psn fake.rif content id
def GetPSNFakeRifContentID(fakerif_file):
    try:
        with open(workbin_file, "rb") as f:
            f.seek(0x50)
            return f.read(0x24).decode("utf-8")
    except:
        pass
    return None

# Get psn package info
def GetPSNPackageInfo(pkg_file, verbose = False, exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return None

    # Get script
    extract_script = None
    if programs.IsToolInstalled("PSNGetPkgInfo"):
        extract_script = programs.GetToolProgram("PSNGetPkgInfo")
    if not extract_script:
        system.LogError("PSNGetPkgInfo was not found")
        return None

    # Get info command
    info_cmd = [
        python_tool,
        extract_script,
        pkg_file
    ]

    # Run info command
    info_output = command.RunOutputCommand(
        cmd = info_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not info_output or len(info_output) == 0:
        return None

    # Parse info
    info = {}
    for line in info_output.split("\n"):
        line_tokens = line.split(":")
        if len(len_tokens) < 2:
            continue
        line_field = line_tokens[0].strip()
        line_value = line_tokens[1].strip()
        if line_field == "NPS Type":
            info["nps_type"] = line_value
        elif line_field == "Title ID":
            info["title_id"] = line_value
        elif line_field == "Title":
            info["title"] = line_value
        elif line_field == "Region":
            info["region"] = line_value
        elif line_field == "Content ID":
            info["content_id"] = line_value
        elif line_field == "Content Type":
            info["content_type"] = line_value
        elif line_field == "DRM Type":
            info["drm_type"] = line_value
        elif line_field == "Min FW":
            info["min_fw"] = line_value
        elif line_field == "Version":
            info["version"] = line_value
        elif line_field == "App Ver":
            info["app_ver"] = line_value
        elif line_field == "Size":
            info["size"] = line_value
    return info

# Rename psn package file
def RenamePSNPackageFile(pkg_file, verbose = False, exit_on_failure = False):
    content_id = GetPSNPackageContentID(pkg_file)
    if not content_id:
        return False
    return system.MoveFileOrDirectory(
        src = pkg_file,
        dest = os.path.join(system.GetFilenameDirectory(pkg_file), content_id + ".pkg"),
        skip_existing = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Rename psn rap file
def RenamePSNRapFile(rap_file, verbose = False, exit_on_failure = False):
    pkg_file = os.path.join(system.GetFilenameDirectory(rap_file), system.GetFilenameBasename(rap_file) + ".pkg")
    if not os.path.isfile(pkg_file):
        return False
    content_id = GetPSNPackageContentID(pkg_file)
    if not content_id:
        return False
    return system.MoveFileOrDirectory(
        src = rap_file,
        dest = os.path.join(system.GetFilenameDirectory(rap_file), content_id + ".rap"),
        skip_existing = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Rename psn work.bin file
def RenamePSNWorkBinFile(workbin_file, verbose = False, exit_on_failure = False):
    content_id = GetPSNWorkBinContentID(workbin_file)
    if not content_id:
        return False
    return system.MoveFileOrDirectory(
        src = workbin_file,
        dest = os.path.join(system.GetFilenameDirectory(workbin_file), content_id + ".work.bin"),
        skip_existing = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Rename psn fake.rif file
def RenamePSNFakeRifFile(fakerif_file, verbose = False, exit_on_failure = False):
    content_id = GetPSNFakeRifContentID(fakerif_file)
    if not content_id:
        return False
    return system.MoveFileOrDirectory(
        src = fakerif_file,
        dest = os.path.join(system.GetFilenameDirectory(fakerif_file), content_id + ".fake.rif"),
        skip_existing = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
