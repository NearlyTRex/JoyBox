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

# Determine if file is an archive
def is_archive(archive_file):
    if is_zip_archive(archive_file):
        return True
    if is_7z_archive(archive_file):
        return True
    if is_rar_archive(archive_file):
        return True
    if is_lzh_archive(archive_file):
        return True
    if is_stuffit_archive(archive_file):
        return True
    if is_tarball_archive(archive_file):
        return True
    if is_disc_archive(archive_file):
        return True
    if is_exe_archive(archive_file):
        return True
    if is_appimage_archive(archive_file):
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

# The archive type matching the extension, else sniffed from the file's mime type; None when unknown
def get_archive_type(archive_file):
    archive_ext = paths.get_filename_extension(archive_file)
    for archive_type in config.ArchiveFileType.members():
        if archive_ext == archive_type.cval():
            return archive_type
    if paths.is_path_file(archive_file):
        if is_zip_archive(archive_file):
            return config.ArchiveFileType.ZIP
        if is_7z_archive(archive_file):
            return config.ArchiveFileType.SEVENZIP
        if is_rar_archive(archive_file):
            return config.ArchiveFileType.RAR
        if is_lzh_archive(archive_file):
            return config.ArchiveFileType.LZH
        if is_stuffit_archive(archive_file):
            return config.ArchiveFileType.SIT
        if is_tarball_archive(archive_file):
            return config.ArchiveFileType.TAR_GZ
        if is_disc_archive(archive_file):
            return config.ArchiveFileType.ISO
    return None

# Determine if creatable archive type
def is_creatable_archive_type(archive_type):
    if archive_type in config.ArchiveZipFileType.members():
        return True
    if archive_type in config.Archive7zFileType.members():
        return True
    return False

# Determine if extractable archive type
def is_extractable_archive_type(archive_type):
    if archive_type in config.ArchiveZipFileType.members():
        return True
    if archive_type in config.Archive7zFileType.members():
        return True
    if archive_type in config.ArchiveRarFileType.members():
        return True
    if archive_type in config.ArchiveLzhFileType.members():
        return True
    if archive_type in config.ArchiveStuffItFileType.members():
        return True
    if archive_type in config.ArchiveTarballFileType.members():
        return True
    if archive_type in config.ArchiveDiscFileType.members():
        return True
    if archive_type == config.ArchiveFileType.EXE:
        return True
    return False

# Check archive checksums
def get_archive_checksums(archive_file):
    checksums = []
    if paths.is_path_file(archive_file):
        if is_zip_archive(archive_file):
            with zipfile.ZipFile(archive_file) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    entry = {}
                    entry["path"] = info.filename
                    entry["crc"] = "%08x" % info.CRC
                    checksums.append(entry)
    return checksums
