# Imports
import os, os.path
import sys
import textwrap

# Local imports
import config
import command
import programs
import system
import hashing
import webpage

######################################################
# Nintendo DS
######################################################

# Encrypt Nintendo DS rom
def EncryptNDSRom(
    nds_file,
    generate_hash = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    encrypt_tool = None
    if programs.IsToolInstalled("NDecrypt"):
        encrypt_tool = programs.GetToolProgram("NDecrypt")
    if not encrypt_tool:
        system.LogError("NDecrypt was not found")
        return False

    # Get encrypt command
    encrypt_cmd = [encrypt_tool]
    encrypt_cmd += ["e"]
    if generate_hash:
        encrypt_cmd += ["-h"]
    encrypt_cmd += [nds_file]

    # Run encrypt command
    code = command.RunReturncodeCommand(
        cmd = encrypt_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [encrypt_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

# Decrypt Nintendo DS rom
def DecryptNDSRom(
    nds_file,
    generate_hash = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    decrypt_tool = None
    if programs.IsToolInstalled("NDecrypt"):
        decrypt_tool = programs.GetToolProgram("NDecrypt")
    if not decrypt_tool:
        system.LogError("NDecrypt was not found")
        return False

    # Get decrypt command
    decrypt_cmd = [decrypt_tool]
    decrypt_cmd += ["d"]
    if generate_hash:
        decrypt_cmd += ["-h"]
    decrypt_cmd += [nds_file]

    # Run decrypt command
    code = command.RunReturncodeCommand(
        cmd = decrypt_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [decrypt_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

######################################################
# Nintendo 3DS
######################################################

# Convert 3DS CIA file to CCI file
def Convert3DSCIAtoCCI(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    convert_tool = None
    if programs.IsToolInstalled("CtrMakeRom"):
        convert_tool = programs.GetToolProgram("CtrMakeRom")
    if not convert_tool:
        system.LogError("CtrMakeRom was not found")
        return False

    # Get convert command
    convert_cmd = [
        convert_tool,
        "-ciatocci",
        src_3ds_file,
        "-o", dest_3ds_file
    ]

    # Run convert command
    code = command.RunReturncodeCommand(
        cmd = convert_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [convert_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(dest_3ds_file)

# Convert 3DS CCI file to CIA file
def Convert3DSCCItoCIA(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    convert_tool = None
    if programs.IsToolInstalled("CtrMakeRom"):
        convert_tool = programs.GetToolProgram("CtrMakeRom")
    if not convert_tool:
        system.LogError("CtrMakeRom was not found")
        return False

    # Get convert command
    convert_cmd = [
        convert_tool,
        "-ccitocia",
        src_3ds_file,
        "-o", dest_3ds_file
    ]

    # Run convert command
    code = command.RunReturncodeCommand(
        cmd = convert_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [convert_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(dest_3ds_file)

# Trim 3DS CCI file
def Trim3DSCCI(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    trim_tool = None
    if programs.IsToolInstalled("3DSRomTool"):
        trim_tool = programs.GetToolProgram("3DSRomTool")
    if not trim_tool:
        system.LogError("3DSRomTool was not found")
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose, pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_3ds_file = system.JoinPaths(tmp_dir_result, "temp.3ds")

    # Copy source file
    system.CopyFileOrDirectory(
        src = src_3ds_file,
        dest = tmp_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    trim_cmd = [
        trim_tool,
        "--trim",
        tmp_3ds_file
    ]

    # Run trim command
    code = command.RunReturncodeCommand(
        cmd = trim_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [trim_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    system.MoveFileOrDirectory(
        src = tmp_3ds_file,
        dest = dest_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_3ds_file)

# Untrim 3DS CCI file
def Untrim3DSCCI(
    src_3ds_file,
    dest_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    trim_tool = None
    if programs.IsToolInstalled("3DSRomTool"):
        trim_tool = programs.GetToolProgram("3DSRomTool")
    if not trim_tool:
        system.LogError("3DSRomTool was not found")
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_3ds_file = system.JoinPaths(tmp_dir_result, "temp.3ds")

    # Copy source file
    system.CopyFileOrDirectory(
        src = src_3ds_file,
        dest = tmp_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    trim_cmd = [
        trim_tool,
        "--restore",
        tmp_3ds_file
    ]

    # Run trim command
    code = command.RunReturncodeCommand(
        cmd = trim_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [trim_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    system.MoveFileOrDirectory(
        src = tmp_3ds_file,
        dest = dest_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_3ds_file)

# Extract 3DS CIA file
def Extract3DSCIA(
    src_3ds_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = None
    if programs.IsToolInstalled("CtrTool"):
        extract_tool = programs.GetToolProgram("CtrTool")
    if not extract_tool:
        system.LogError("CtrTool was not found")
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Get temporary files
    tmp_file_cer = system.JoinPaths(tmp_dir_result, "00000000.cer")
    tmp_file_tik = system.JoinPaths(tmp_dir_result, "00000000.tik")
    tmp_file_tmd = system.JoinPaths(tmp_dir_result, "00000000.tmd")
    tmp_base_contents = system.JoinPaths(tmp_dir_result, "contents")

    # Get extract command
    extract_cmd = [
        extract_tool,
        "--contents", tmp_base_contents,
        "--certs", tmp_file_cer,
        "--tik", tmp_file_tik,
        "--tmd", tmp_file_tmd,
        src_3ds_file
    ]

    # Run extract command
    code = command.RunReturncodeCommand(
        cmd = extract_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Rename app files
    for obj in system.GetDirectoryContents(tmp_dir_result):
        if obj.startswith("contents"):
            obj_path = system.JoinPaths(tmp_dir_result, obj)
            obj_basename = system.GetFilenameExtension(obj).strip(".")
            system.MoveFileOrDirectory(
                src = obj_path,
                dest = system.JoinPaths(tmp_dir_result, obj_basename + ".app"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Move extracted files
    system.MoveContents(
        src = tmp_dir_result,
        dest = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir) and not system.IsDirectoryEmpty(extract_dir)

# Get 3DS file info
def Get3DSFileInfo(
    src_3ds_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    print_tool = None
    if programs.IsToolInstalled("CtrTool"):
        print_tool = programs.GetToolProgram("CtrTool")
    if not print_tool:
        system.LogError("CtrTool was not found")
        return ""

    # Get print command
    print_cmd = [
        print_tool,
        src_3ds_file
    ]

    # Run print command
    output = command.RunOutputCommand(
        cmd = print_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [print_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return output

# Install 3DS CIA file
def Install3DSCIA(
    src_3ds_file,
    sdmc_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get file info
    file_info = Get3DSFileInfo(
        src_3ds_file = src_3ds_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(file_info) == 0:
        return False

    # Get title id
    app_titleid = ""
    for line in file_info.split("\n"):
        if line.startswith("Title id:"):
            line_tokens = line.split(":")
            if len(line_tokens) == 2:
                app_titleid = line_tokens[1].strip()
                break
    if len(app_titleid) != 16:
        return False

    # Get app info
    app_type = app_titleid[:8].lower()
    app_folder = app_titleid[8:].lower()
    app_base_dir = system.JoinPaths(sdmc_dir, "Nintendo 3DS", "00000000000000000000000000000000", "00000000000000000000000000000000", "title")
    app_install_dir = system.JoinPaths(app_base_dir, app_type, app_folder, "content")

    # Extract cia file
    success = Extract3DSCIA(
        src_3ds_file = src_3ds_file,
        extract_dir = app_install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Should be installed
    return True

######################################################
# Nintendo Wii U
######################################################

# Decrypt Wii U NUS package
def DecryptWiiUNUSPackage(
    nus_package_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    decrypt_tool = None
    if programs.IsToolInstalled("CDecrypt"):
        decrypt_tool = programs.GetToolProgram("CDecrypt")
    if not decrypt_tool:
        system.LogError("CDecrypt was not found")
        return False

    # Get input files
    input_file_tmd = system.JoinPaths(nus_package_dir, "title.tmd")
    input_file_tik = system.JoinPaths(nus_package_dir, "title.tik")
    if not os.path.exists(input_file_tmd) or not os.path.exists(input_file_tik):
        return False

    # Get decrypt command
    decrypt_cmd = [
        decrypt_tool,
        input_file_tmd,
        input_file_tik
    ]

    # Run decrypt command
    code = command.RunReturncodeCommand(
        cmd = decrypt_cmd,
        options = command.CreateCommandOptions(
            cwd = nus_package_dir,
            output_paths = [nus_package_dir],
            blocking_processes = [decrypt_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        for obj in system.GetDirectoryContents(nus_package_dir):
            obj_path = system.JoinPaths(nus_package_dir, obj)
            if not system.IsPathFile(obj_path):
                continue
            obj_ext = system.GetFilenameExtension(obj_path)
            if obj_ext in config.NintendoWiiUFileType.cvalues():
                system.RemoveFile(
                    src = obj_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

    # Should be decrypted now
    return True

# Verify Wii U NUS package
def VerifyWiiUNUSPackage(
    nus_package_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Copy package
    system.CopyContents(
        src = nus_package_dir,
        dest = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Test decryption
    decryption_result = DecryptWiiUNUSPackage(
        nus_package_dir = nus_package_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return decryption_result

# Install Wii U NUS package
def InstallWiiUNusPackage(
    nus_package_dir,
    nand_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Copy package
    system.CopyContents(
        src = nus_package_dir,
        dest = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if system.IsDirectoryEmpty(tmp_dir_result):
        return False

    # Decrypt package
    success = DecryptWiiUNUSPackage(
        nus_package_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get app xml
    app_xml_file = system.JoinPaths(tmp_dir_result, "code", "app.xml")
    if not os.path.exists(app_xml_file):
        return False

    # Get title id
    app_titleid = ""
    with open(app_xml_file, "r") as f:
        data = f.read()
        soup = webpage.ParseXmlPageSource(data)
        if soup:
            for tag in soup.find_all("title_id"):
                app_titleid = tag.text
    if len(app_titleid) != 16:
        return False

    # Get app info
    app_type = app_titleid[:8].lower()
    app_folder = app_titleid[8:].lower()

    # Look at each extracted folder
    for obj in ["code", "content", "meta"]:

        # Make folder
        success = system.MakeDirectory(
            src = system.JoinPaths(tmp_dir_result, obj),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Move folder
        success = system.MoveFileOrDirectory(
            src = system.JoinPaths(tmp_dir_result, obj),
            dest = system.JoinPaths(nand_dir, "usr", "title", app_type, app_folder, obj),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be installed
    return True

# Update Wii U keys file
def UpdateWiiUKeys(
    src_key_file,
    dest_key_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Read existing keys
    existing_keys = set()
    with open(dest_key_file, "r") as f:
        for line in f.readlines():
            existing_keys.add(line.strip())

    # Get new keys
    new_keys = set()
    with open(src_key_file, "r") as f:
        for line in f.readlines():
            new_keys.add(line.strip())

    # Update keys
    updated_keys = existing_keys.union(new_keys)

    # Write keys
    with open(dest_key_file, "w") as f:
        for key in sorted(updated_keys):
            f.write("%s\n" % key)

######################################################
# Nintendo Switch
######################################################

# Check if switch profile info is valid
def IsValidSwitchProfileInfo(user_id, account_name):

    # Check user id
    if not isinstance(user_id, str) or len(user_id) != 32:
        return False

    # Check account name
    if not isinstance(account_name, str) or len(account_name) > 32:
        return False

    # Should be good
    return True

# Create Switch profiles dat
def CreateSwitchProfilesDat(
    profiles_file,
    user_id,
    account_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check profile info
    if not IsValidSwitchProfileInfo(user_id, account_name):
        return False

    # Get user id bytes
    user_id_bytes = bytearray.fromhex("".join(reversed(textwrap.wrap(user_id, 2))))
    if len(user_id_bytes) == 0:
        return False

    # Get account name bytes
    account_name_bytes = bytearray(account_name, encoding = "utf-8")
    if len(account_name_bytes) == 0:
        return False

    # Initialize file contents
    file_contents = [b'\x00'] * 1616

    # Write user_id_1
    file_index = 0x10
    for offset in range(0, len(user_id_bytes)):
        file_contents[file_index + offset] = bytes([user_id_bytes[offset]])

    # Write user_id_2
    file_index = 0x20
    for offset in range(0, len(user_id_bytes)):
        file_contents[file_index + offset] = bytes([user_id_bytes[offset]])

    # Write account_name
    file_index = 0x38
    for offset in range(0, len(account_name_bytes)):
        file_contents[file_index + offset] = bytes([account_name_bytes[offset]])

    # Write file
    success = system.TouchFile(
        src = profiles_file,
        contents = b"".join(file_contents),
        contents_mode = "wb",
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return os.path.exists(profiles_file)

# Trim Switch XCI file
def TrimSwitchXCI(
    src_xci_file,
    dest_xci_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    trim_script = None
    if programs.IsToolInstalled("XCITrimmer"):
        trim_script = programs.GetToolProgram("XCITrimmer")
    if not trim_script:
        system.LogError("XCITrimmer was not found")
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose, pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_xci_basename = system.GetFilenameBasename(src_xci_file)
    tmp_xci_src_file = system.JoinPaths(tmp_dir_result, tmp_xci_basename + ".xci")
    tmp_xci_dest_file = system.JoinPaths(tmp_dir_result, tmp_xci_basename + "_trimmed.xci")

    # Copy source file
    system.CopyFileOrDirectory(
        src = src_xci_file,
        dest = tmp_xci_src_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    trim_cmd = [
        python_tool,
        trim_script,
        "--trim",
        "--copy",
        tmp_xci_src_file
    ]

    # Run trim command
    code = command.RunReturncodeCommand(
        cmd = trim_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    system.MoveFileOrDirectory(
        src = tmp_xci_dest_file,
        dest = dest_xci_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveFile(
            src = src_xci_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_xci_file)

# Untrim Switch XCI file
def UntrimSwitchXCI(
    src_xci_file,
    dest_xci_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    untrim_script = None
    if programs.IsToolInstalled("XCITrimmer"):
        untrim_script = programs.GetToolProgram("XCITrimmer")
    if not untrim_script:
        system.LogError("XCITrimmer was not found")
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose, pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    tmp_xci_basename = system.GetFilenameBasename(src_xci_file)
    tmp_xci_src_file = system.JoinPaths(tmp_dir_result, tmp_xci_basename + ".xci")
    tmp_xci_dest_file = system.JoinPaths(tmp_dir_result, tmp_xci_basename + "_padded.xci")

    # Copy source file
    system.CopyFileOrDirectory(
        src = src_xci_file,
        dest = tmp_xci_src_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get trim command
    untrim_cmd = [
        python_tool,
        untrim_script,
        "--pad",
        "--copy",
        tmp_xci_src_file
    ]

    # Run untrim command
    code = command.RunReturncodeCommand(
        cmd = untrim_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Move new file
    system.MoveFileOrDirectory(
        src = tmp_xci_dest_file,
        dest = dest_xci_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveFile(
            src = src_xci_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(dest_xci_file)

# Extract Switch NSP file
def ExtractSwitchNSP(
    nsp_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = None
    if programs.IsToolInstalled("HacTool"):
        extract_tool = programs.GetToolProgram("HacTool")
    if not extract_tool:
        system.LogError("HacTool was not found")
        return False

    # Get extract command
    extract_cmd = [
        extract_tool,
        "-r",
        "-t", "pfs0",
        "--outdir", extract_dir,
        nsp_file
    ]

    # Run extract command
    code = command.RunReturncodeCommand(
        cmd = extract_cmd,
        options = command.CreateCommandOptions(
            output_paths = [extract_dir],
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(extract_dir) and not system.IsDirectoryEmpty(extract_dir)

# Install Switch NSP file
def InstallSwitchNSP(
    nsp_file,
    nand_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Extract nsp file
    success = ExtractSwitchNSP(
        nsp_file = nsp_file,
        extract_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Look at all the extracted nca files
    for nca_file in system.BuildFileListByExtensions(tmp_dir_result, extensions = [".nca"]):

        # Get NCA id
        nca_id = system.GetFilenameBasename(nca_file)
        if nca_id.endswith(".cnmt"):
            nca_id = system.GetFilenameBasename(nca_id)

        # Get NCA dir
        nca_id_bytes = bytes.fromhex(nca_id)
        nca_id_sha256 = hashing.CalculateStringSHA256(nca_id_bytes).upper()
        nca_id_dir = "000000%s" % nca_id_sha256[0:2]
        nca_output_dir = system.JoinPaths(nand_dir, "user", "Contents", "registered", nca_id_dir)

        # Make NCA dir
        success = system.MakeDirectory(
            src = nca_output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Copy NCA file
        success = system.CopyFileOrDirectory(
            src = nca_file,
            dest = system.JoinPaths(nca_output_dir, nca_id + ".nca"),
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be installed
    return True
