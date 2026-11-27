# Imports
import os
import os.path
import struct
import zlib
import base64

# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import fileops
from joybox import fileedits
from joybox import iso
from joybox import chd
from joybox import runtime

######################################################
# Sony PlayStation 3
######################################################

# Files a decrypted ps3 iso holds, and the header each starts with when the decryption held
PS3_DECRYPTED_HEADERS = [
    (("PS3_GAME", "LICDIR", "LIC.DAT"), "PS3LICDA"),
    (("PS3_GAME", "USRDIR", "EBOOT.BIN"), "SCE")
]

# Hex key text from a .dkey file, stripped; empty when the file is missing or unreadable
def get_ps3_decryption_key(dkey_file):
    if not os.path.exists(dkey_file):
        return ""
    return (serialization.read_text_file(dkey_file) or "").strip()

# Run a conversion command, logging the failure given when it does not succeed
def run_conversion_command(cmd, failure_message, verbose = False, pretend_run = False, exit_on_failure = False):
    code = command.run_returncode_command(
        cmd = cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        if exit_on_failure:
            logger.log_error(failure_message, quit_program = True)
        return False
    return True

# Finish a conversion: remove its source when asked, and check its result exists
def finish_conversion(src, dest, delete_original = False, verbose = False, pretend_run = False, exit_on_failure = False):
    if delete_original:
        fileops.remove_file(
            src = src,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return os.path.exists(dest)

# Encrypt or decrypt a ps3 iso with PS3Dec, in mode "e" or "d", using the key in a key file
def crypt_ps3_iso(mode, src_iso_file, dest_iso_file, dkey_file, failure_message, verbose = False, pretend_run = False, exit_on_failure = False):
    crypt_tool = programs.find_tool_program("PS3Dec")
    if not crypt_tool:
        return False
    key = get_ps3_decryption_key(dkey_file)
    if len(key) == 0:
        if exit_on_failure:
            logger.log_error("PS3 key file '%s' is invalid" % dkey_file, quit_program = True)
        return False
    if not run_conversion_command(
        [crypt_tool, mode, "key", key, src_iso_file, dest_iso_file], failure_message, verbose, pretend_run, exit_on_failure):
        return False
    return os.path.exists(dest_iso_file)

# Re-encrypt a decrypted ps3 iso with PS3Dec and the .dkey key; True when the output exists
def encrypt_ps3_iso(
    iso_file_dec,
    iso_file_enc,
    dkey_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return crypt_ps3_iso(
        "e", iso_file_dec, iso_file_enc, dkey_file,
        "Unable to encrypt ps3 iso '%s' to '%s'" % (iso_file_dec, iso_file_enc),
        verbose, pretend_run, exit_on_failure)

# Decrypt a ps3 iso with PS3Dec and the .dkey key; True when the output exists
def decrypt_ps3_iso(
    iso_file_enc,
    iso_file_dec,
    dkey_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return crypt_ps3_iso(
        "d", iso_file_enc, iso_file_dec, dkey_file,
        "Unable to decrypt ps3 iso '%s' to '%s'" % (iso_file_enc, iso_file_dec),
        verbose, pretend_run, exit_on_failure)

# Check a file extracted from a decrypted ps3 iso, when there, has the header it should;
# a wrong one means the decryption key did not fit the iso
def is_ps3_file_decrypted(extract_dir, rel_path, header, dkey_file, iso_file, exit_on_failure = False):
    file_path = paths.join_paths(extract_dir, *rel_path)
    if not os.path.exists(file_path) or fileedits.is_file_correctly_headered(file_path, header):
        return True
    if exit_on_failure:
        logger.log_error("Decryption failure, %s '%s' has the wrong header (expected %s)." % (rel_path[-1], file_path, header))
        logger.log_error("It seems likely that the decryption key file '%s' is not compatible with '%s'" % (dkey_file, iso_file))
        runtime.quit_program()
    return False

# Decrypt to a .dec.iso beside the source, extract it, and check the LIC.DAT and EBOOT.BIN headers prove the key fit
def extract_ps3_iso(
    iso_file,
    dkey_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Decrypt the iso and extract the decrypted copy
    iso_file_dec = paths.join_paths(paths.get_filename_directory(iso_file), paths.get_filename_basename(iso_file) + ".dec.iso")
    success = decrypt_ps3_iso(
        iso_file_enc = iso_file,
        iso_file_dec = iso_file_dec,
        dkey_file = dkey_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    success = iso.extract_iso(
        iso_file = iso_file_dec,
        extract_dir = extract_dir,
        delete_original = delete_original,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check the decryption held by the extracted files' headers
    for rel_path, header in PS3_DECRYPTED_HEADERS:
        if not is_ps3_file_decrypted(extract_dir, rel_path, header, dkey_file, iso_file, exit_on_failure):
            return False
    return finish_conversion(iso_file_dec, extract_dir, delete_original, verbose, pretend_run, exit_on_failure)

# Extract a ps3 chd within a scratch directory and decrypt it, checking the decryption held
def extract_and_decrypt_ps3_chd(chd_file, tmp_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    iso_tmp_dir = paths.join_paths(tmp_dir, "iso")
    raw_tmp_dir = paths.join_paths(tmp_dir, "raw")
    chd_basename = paths.get_filename_basename(chd_file)
    iso_bin_file = paths.join_paths(iso_tmp_dir, chd_basename + config.DiscImageFileType.ISO.cval())
    for directory in (iso_tmp_dir, raw_tmp_dir):
        fileops.make_directory(
            src = directory,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    success = chd.extract_disc_chd(
        chd_file = chd_file,
        binary_file = iso_bin_file,
        toc_file = paths.join_paths(iso_tmp_dir, chd_basename + ".toc"),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return extract_ps3_iso(
        iso_file = iso_bin_file,
        dkey_file = paths.join_paths(paths.get_filename_directory(chd_file), chd_basename + ".dkey"),
        extract_dir = raw_tmp_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Whether a ps3 chd extracts and decrypts cleanly with the .dkey beside it, working in a temporary directory
def verify_ps3_chd(
    chd_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Extract and decrypt in a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        return extract_and_decrypt_ps3_chd(chd_file, tmp_dir, verbose, pretend_run, exit_on_failure)

# Unpack a psn pkg's content into extract_dir with PSNGetPkgInfo; True when the directory exists after
def extract_psn_pkg(
    pkg_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    script_cmd = programs.get_python_script_command("PSNGetPkgInfo")
    if not script_cmd:
        return False
    if not run_conversion_command(
        script_cmd + ["--content", extract_dir, pkg_file],
        "Unable to extract psn pkg '%s' to '%s'" % (pkg_file, extract_dir),
        verbose, pretend_run, exit_on_failure):
        return False
    return finish_conversion(pkg_file, extract_dir, delete_original, verbose, pretend_run, exit_on_failure)

######################################################
# Sony PlayStation Vita
######################################################

# Strip psv file
def strip_psv(
    src_psv_file,
    dest_psv_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    strip_tool = programs.find_tool_program("PSVStrip")
    if not strip_tool:
        return False
    if not run_conversion_command(
        [strip_tool, "-psvstrip", src_psv_file, dest_psv_file],
        "Unable to strip psv file '%s'" % src_psv_file,
        verbose, pretend_run, exit_on_failure):
        return False
    return finish_conversion(src_psv_file, dest_psv_file, delete_original, verbose, pretend_run, exit_on_failure)

# Unstrip psv file
def unstrip_psv(
    src_psv_file,
    src_psve_file,
    dest_psv_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    unstrip_tool = programs.find_tool_program("PSVStrip")
    if not unstrip_tool:
        return False
    if not run_conversion_command(
        [unstrip_tool, "-applypsve", src_psv_file, dest_psv_file, src_psve_file],
        "Unable to unstrip psv file '%s'" % src_psv_file,
        verbose, pretend_run, exit_on_failure):
        return False
    return finish_conversion(src_psv_file, dest_psv_file, delete_original, verbose, pretend_run, exit_on_failure)

# Run PSVTools with the arguments given, logging the failure given when it does not succeed
def run_psv_tools(args, failure_message, verbose = False, pretend_run = False, exit_on_failure = False):
    script_cmd = programs.get_python_script_command("PSVTools")
    if not script_cmd:
        return False
    return run_conversion_command(script_cmd + args, failure_message, verbose, pretend_run, exit_on_failure)

# Trim psv file
def trim_psv(
    src_psv_file,
    dest_psv_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not run_psv_tools(
        ["--trim", "-o", dest_psv_file, src_psv_file],
        "Unable to trim psv file '%s'" % src_psv_file,
        verbose, pretend_run, exit_on_failure):
        return False
    return finish_conversion(src_psv_file, dest_psv_file, delete_original, verbose, pretend_run, exit_on_failure)

# Untrim psv file
def untrim_psv(
    src_psv_file,
    dest_psv_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not run_psv_tools(
        ["--expand", "-o", dest_psv_file, src_psv_file],
        "Unable to untrim psv file '%s'" % src_psv_file,
        verbose, pretend_run, exit_on_failure):
        return False
    return finish_conversion(src_psv_file, dest_psv_file, delete_original, verbose, pretend_run, exit_on_failure)

# Verify psv file
def verify_psv(
    psv_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_psv_tools(
        ["--verify", psv_file],
        "Unable to verify psv file '%s'" % psv_file,
        verbose, pretend_run, exit_on_failure)

# Read param.sfo values
def read_param_sfo(sfo_file):
    data = serialization.read_binary_file(sfo_file)
    if data is None:
        return None
    try:
        magic, _, key_table, data_table, count = struct.unpack_from("<4sIIII", data, 0)
        if magic != b"\x00PSF":
            return None
        values = {}
        for index in range(count):
            key_offset, data_fmt, data_len, _, data_offset = struct.unpack_from("<HHIII", data, 20 + index * 16)
            key = data[key_table + key_offset:].split(b"\x00", 1)[0].decode("utf-8")
            raw = data[data_table + data_offset:data_table + data_offset + data_len]
            if data_fmt == 0x0404:
                values[key] = struct.unpack_from("<I", raw)[0]
            else:
                values[key] = raw.split(b"\x00", 1)[0].decode("utf-8")
        return values
    except (struct.error, UnicodeDecodeError):
        return None

# Find psv content root (the dir holding sce_sys/param.sfo)
def find_psv_content_root(search_dir, title_id):
    content_roots = []
    for root, dirs, _ in os.walk(search_dir):
        dirs.sort()
        sfo_file = paths.join_paths(root, "sce_sys", "param.sfo")
        if not os.path.isfile(sfo_file):
            continue
        sfo_values = read_param_sfo(sfo_file) or {}
        if sfo_values.get("TITLE_ID") == title_id:
            return root
        content_roots.append(root)
        dirs.clear()
    if len(content_roots) == 1:
        return content_roots[0]
    return None

######################################################
# Sony PlayStation Network
######################################################

# The psn package info fields kept, by the name PSNGetPkgInfo prints them under
PSN_PACKAGE_INFO_FIELDS = {
    "NPS Type": "nps_type",
    "Title ID": "title_id",
    "Title": "title",
    "Region": "region",
    "Content ID": "content_id",
    "Content Type": "content_type",
    "DRM Type": "drm_type",
    "Min FW": "min_fw",
    "Version": "version",
    "App Ver": "app_ver",
    "Size": "size"
}

# Get psn work.bin bytes from zrif string
def get_psn_workbin_bytes_from_zrif_string(zrif_str):
    try:
        zrif_base64 = b"eNpjYBgFo2AU0AsYAIElGt8MRJiDCAsw3xhEmIAIU4N4AwNdRxcXZ3+/EJCAkW6Ac7C7ARwYgviuQAaIdoPSzlDaBUo7QmknIM3ACIZM78+u7kx3VWYEAGJ9HV0="
        zrif_dict = list(zlib.decompress(base64.b64decode(zrif_base64)))
        zrif_str_bytes = base64.b64decode(zrif_str.encode("ascii"))
        zrif_decompressor = zlib.decompressobj(wbits=10, zdict=bytes(zrif_dict))
        workbin_bytes = zrif_decompressor.decompress(zrif_str_bytes)
        workbin_bytes += zrif_decompressor.flush()
        return workbin_bytes
    except (ValueError, zlib.error):
        return None

# A content id read out of a file, or None when it could not be read or is not text
def decode_content_id(data):
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None

# Content id stored at offset 0x30 of a pkg file; None when unreadable or not text
def get_psn_package_content_id(pkg_file):
    return decode_content_id(serialization.read_binary_file(pkg_file, offset = 0x30, length = 0x24))

# Get psn work.bin content id
def get_psn_workbin_content_id(workbin_file):
    return decode_content_id(serialization.read_binary_file(workbin_file, offset = 0x10, length = 0x24))

# Get psn fake.rif content id
def get_psn_fakerif_content_id(fakerif_file):
    return decode_content_id(serialization.read_binary_file(fakerif_file, offset = 0x50, length = 0x24))

# Parse the "Field: value" lines of a psn package's info, keeping the fields it knows
def parse_psn_package_info(info_output):
    info = {}
    for line in info_output.split("\n"):
        line_field, separator, line_value = line.partition(":")
        info_key = PSN_PACKAGE_INFO_FIELDS.get(line_field.strip())
        if separator and info_key:
            info[info_key] = line_value.strip()
    return info

# Title, region, content id and the other fields PSNGetPkgInfo reports for a pkg; None when it fails
def get_psn_package_info(
    pkg_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    script_cmd = programs.get_python_script_command("PSNGetPkgInfo")
    if not script_cmd:
        return None
    info_output = command.run_output_command(
        cmd = script_cmd + [pkg_file],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not info_output:
        return None
    return parse_psn_package_info(info_output)

# Rename a pkg to <content id>.pkg in place, leaving an existing target alone; False without an id
def rename_psn_package_file(
    pkg_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    content_id = get_psn_package_content_id(pkg_file)
    if not content_id:
        return False
    return fileops.move_file_or_directory(
        src = pkg_file,
        dest = paths.join_paths(paths.get_filename_directory(pkg_file), content_id + ".pkg"),
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Rename a rap to <content id>.rap using the pkg of the same base name beside it; False without that pkg
def rename_psn_rap_file(
    rap_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    pkg_file = paths.join_paths(paths.get_filename_directory(rap_file), paths.get_filename_basename(rap_file) + ".pkg")
    if not paths.is_path_file(pkg_file):
        return False
    content_id = get_psn_package_content_id(pkg_file)
    if not content_id:
        return False
    return fileops.move_file_or_directory(
        src = rap_file,
        dest = paths.join_paths(paths.get_filename_directory(rap_file), content_id + ".rap"),
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Rename psn work.bin file
def rename_psn_workbin_file(
    workbin_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    content_id = get_psn_workbin_content_id(workbin_file)
    if not content_id:
        return False
    return fileops.move_file_or_directory(
        src = workbin_file,
        dest = paths.join_paths(paths.get_filename_directory(workbin_file), content_id + ".work.bin"),
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Rename psn fake.rif file
def rename_psn_fakerif_file(
    fakerif_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    content_id = get_psn_fakerif_content_id(fakerif_file)
    if not content_id:
        return False
    return fileops.move_file_or_directory(
        src = fakerif_file,
        dest = paths.join_paths(paths.get_filename_directory(fakerif_file), content_id + ".fake.rif"),
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
