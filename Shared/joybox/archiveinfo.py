# What kind of archive a file is and what it holds, read without running any
# archive tool, so file comparisons below the command layer can use it.

# Imports
import zipfile

# Local imports
from joybox import config
from joybox import paths

# Determine if file is a known archive
def is_known_archive(archive_file, extensions = (), mime_types = ()):
    for ext in extensions:
        if archive_file.lower().endswith(ext.lower()):
            return True
    if not paths.is_path_file(archive_file):
        return False
    actual_mime_type = paths.get_file_mime_type(archive_file)
    for potential_mime_type in mime_types:
        if potential_mime_type.lower() in actual_mime_type.lower():
            return True
    return False

# Determine if file is a zip archive
def is_zip_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveZipFileType.cvalues(),
        mime_types = config.mime_types_zip)

# Determine if file is a 7z archive
def is_7z_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.Archive7zFileType.cvalues(),
        mime_types = config.mime_types_7z)

# Determine if file is a rar archive
def is_rar_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveRarFileType.cvalues(),
        mime_types = config.mime_types_rar)

# Determine if file is a lzh archive
def is_lzh_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveLzhFileType.cvalues(),
        mime_types = config.mime_types_lzh)

# Determine if file is a stuffit archive
def is_stuffit_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveStuffItFileType.cvalues(),
        mime_types = config.mime_types_stuffit)

# Determine if file is a tarball archive
def is_tarball_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveTarballFileType.cvalues(),
        mime_types = config.mime_types_tarball)

# Determine if file is a disc archive
def is_disc_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveDiscFileType.cvalues(),
        mime_types = config.mime_types_disc)

# Determine if file is an exe archive
def is_exe_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = [config.WindowsProgramFileType.EXE.cval()],
        mime_types = config.mime_types_exe)

# Determine if file is an appimage archive
def is_appimage_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = [config.LinuxProgramFileType.APPIMAGE.cval()],
        mime_types = config.mime_types_appimage)

# Every check is_archive tries, in order
ARCHIVE_CHECKS = (
    is_zip_archive,
    is_7z_archive,
    is_rar_archive,
    is_lzh_archive,
    is_stuffit_archive,
    is_tarball_archive,
    is_disc_archive,
    is_exe_archive,
    is_appimage_archive)

# Determine if file is any kind of archive
def is_archive(archive_file):
    return any(check(archive_file) for check in ARCHIVE_CHECKS)

# The archive type each check means when get_archive_type sniffs a file, in the order it tries them
SNIFFED_ARCHIVE_TYPES = (
    (is_zip_archive, config.ArchiveFileType.ZIP),
    (is_7z_archive, config.ArchiveFileType.SEVENZIP),
    (is_rar_archive, config.ArchiveFileType.RAR),
    (is_lzh_archive, config.ArchiveFileType.LZH),
    (is_stuffit_archive, config.ArchiveFileType.SIT),
    (is_tarball_archive, config.ArchiveFileType.TAR_GZ),
    (is_disc_archive, config.ArchiveFileType.ISO))

# The archive type matching the extension, else sniffed from the file's mime type; None when unknown
def get_archive_type(archive_file):
    archive_ext = paths.get_filename_extension(archive_file)
    for archive_type in config.ArchiveFileType.members():
        if archive_ext == archive_type.cval():
            return archive_type
    if paths.is_path_file(archive_file):
        for check, archive_type in SNIFFED_ARCHIVE_TYPES:
            if check(archive_file):
                return archive_type
    return None

# Determine if creatable archive type
def is_creatable_archive_type(archive_type):
    if archive_type in config.ArchiveZipFileType.members():
        return True
    if archive_type in config.Archive7zFileType.members():
        return True
    return False

# Archive type families whose every member can be extracted
EXTRACTABLE_ARCHIVE_FAMILIES = (
    config.ArchiveZipFileType,
    config.Archive7zFileType,
    config.ArchiveRarFileType,
    config.ArchiveLzhFileType,
    config.ArchiveStuffItFileType,
    config.ArchiveTarballFileType,
    config.ArchiveDiscFileType)

# Determine if extractable archive type: any member of an extractable family, or an exe
def is_extractable_archive_type(archive_type):
    if archive_type == config.ArchiveFileType.EXE:
        return True
    return any(archive_type in family.members() for family in EXTRACTABLE_ARCHIVE_FAMILIES)

# {path, crc} for each file entry of an open zip, directories left out
def _get_zip_checksums(zf):
    checksums = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        entry = {}
        entry["path"] = info.filename
        entry["crc"] = "%08x" % info.CRC
        checksums.append(entry)
    return checksums

# Check archive checksums
def get_archive_checksums(archive_file):
    checksums = []
    if paths.is_path_file(archive_file):
        if is_zip_archive(archive_file):
            with zipfile.ZipFile(archive_file) as zf:
                checksums = _get_zip_checksums(zf)
    return checksums
