# Imports
import inspect

# Third-party imports
import pytest

# Local imports
from joybox.config import files
from joybox.config import types

FILE_TYPE_CLASSES = sorted(
    (name, candidate) for name, candidate in inspect.getmembers(files, inspect.isclass)
    if issubclass(candidate, types.EnumType) and candidate is not types.EnumType)
FILE_TYPE_IDS = [name for name, _ in FILE_TYPE_CLASSES]
ARCHIVE_FAMILIES = [
    files.ArchiveZipFileType,
    files.Archive7zFileType,
    files.ArchiveRarFileType,
    files.ArchiveLzhFileType,
    files.ArchiveStuffItFileType,
    files.ArchiveTarballFileType,
    files.ArchiveDiscFileType
]
FAMILY_MEMBERS = [(family, member) for family in ARCHIVE_FAMILIES for member in family]
FAMILY_MEMBER_IDS = ["%s.%s" % (family.__name__, member.name) for family, member in FAMILY_MEMBERS]
ARCHIVE_EXTENSIONS = files.ArchiveFileType.cvalues()


###########################################################
# Every file type enum
###########################################################

def test_every_file_type_enum_is_found():
    assert len(FILE_TYPE_CLASSES) == 14


@pytest.mark.parametrize("enum_class", [candidate for _, candidate in FILE_TYPE_CLASSES], ids = FILE_TYPE_IDS)
def test_extensions_are_unique_dotted_and_unspaced(enum_class):
    extensions = enum_class.cvalues()
    assert len(extensions) == len(set(extensions))
    assert all(extension.startswith(".") and len(extension) > 1 and extension.strip() == extension for extension in extensions)


@pytest.mark.parametrize("enum_class", [candidate for _, candidate in FILE_TYPE_CLASSES], ids = FILE_TYPE_IDS)
def test_type_names_are_unique(enum_class):
    assert len(enum_class.values()) == len(set(enum_class.values()))


###########################################################
# Archive families
###########################################################

@pytest.mark.parametrize("family, member", FAMILY_MEMBERS, ids = FAMILY_MEMBER_IDS)
def test_family_member_mirrors_its_archive_type(family, member):
    archive_type = files.ArchiveFileType[member.name]
    assert member.val() == archive_type.val()
    assert member.cvalue == archive_type.cvalue


def test_archive_families_are_disjoint():
    names = [member.name for _, member in FAMILY_MEMBERS]
    assert len(names) == len(set(names))


def test_only_program_types_fall_outside_every_family():
    unfamilied = {member.name for member in files.ArchiveFileType} - {member.name for _, member in FAMILY_MEMBERS}
    assert unfamilied == {"EXE", "APPIMAGE"}


@pytest.mark.parametrize("archive_type, program_type", [
    (files.ArchiveFileType.EXE, files.WindowsProgramFileType.EXE),
    (files.ArchiveFileType.APPIMAGE, files.LinuxProgramFileType.APPIMAGE)
], ids = ["exe", "appimage"])
def test_self_extracting_archives_match_their_program_type(archive_type, program_type):
    assert archive_type.val() == program_type.val()
    assert archive_type.cvalue == program_type.cvalue


def test_disc_archive_is_a_disc_image():
    assert files.ArchiveDiscFileType.ISO.cvalue in files.DiscImageFileType.cvalues()


@pytest.mark.parametrize("extension", ARCHIVE_EXTENSIONS)
def test_no_archive_extension_hides_another_by_suffix(extension):
    assert [other for other in ARCHIVE_EXTENSIONS if other != extension and other.endswith(extension)] == []


@pytest.mark.parametrize("member", files.ArchiveTarballFileType.members(), ids = files.ArchiveTarballFileType.values())
def test_tarball_extensions_name_a_tarball(member):
    assert member.cvalue.startswith((".tar.", ".t"))
