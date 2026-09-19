# Imports
import pytest

# Local imports
from joybox import archive, config


###########################################################
# Archive type detection
#
# is_archive gates content comparison in hashing and release handling, so a
# type missing from it is silently treated as a plain file.
###########################################################

DETECTORS = [
    ("is_zip_archive", config.ArchiveZipFileType),
    ("is_7z_archive", config.Archive7zFileType),
    ("is_rar_archive", config.ArchiveRarFileType),
    ("is_tarball_archive", config.ArchiveTarballFileType),
    ("is_disc_archive", config.ArchiveDiscFileType),
]


@pytest.mark.parametrize("detector,enum_class", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_each_detector_recognises_its_own_extensions(detector, enum_class):
    check = getattr(archive, detector)

    for extension in enum_class.cvalues():
        assert check(f"file{extension}") is True, f"{detector} missed {extension}"


@pytest.mark.parametrize("detector,enum_class", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_each_detector_is_case_insensitive(detector, enum_class):
    check = getattr(archive, detector)

    for extension in enum_class.cvalues():
        assert check(f"file{extension.upper()}") is True


@pytest.mark.parametrize("detector,_enum", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_no_detector_claims_a_plain_file(detector, _enum):
    assert getattr(archive, detector)("notes.txt") is False


@pytest.mark.parametrize("detector,enum_class", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_every_archive_type_is_an_archive(detector, enum_class):
    # is_archive has to cover every type the codebase can extract.
    for extension in enum_class.cvalues():
        assert archive.is_archive(f"file{extension}") is True, \
            f"is_archive does not recognise {extension}"


def test_rar_counts_as_an_archive():
    # RAR is extractable and has its own detector, so it belongs in is_archive.
    assert archive.is_archive("file.rar") is True
    assert archive.is_extractable_archive_type(config.ArchiveFileType.RAR) is True


def test_executables_and_appimages_count_as_archives():
    assert archive.is_archive("setup.exe") is True
    assert archive.is_archive("app.AppImage") is True


def test_a_plain_file_is_not_an_archive():
    assert archive.is_archive("notes.txt") is False


def test_a_tarball_compound_extension_is_recognised():
    # ".tar.gz" must match as a unit, not as ".gz".
    assert archive.is_tarball_archive("backup.tar.gz") is True


###########################################################
# Archive type resolution
###########################################################

@pytest.mark.parametrize("extension,expected", [
    (".zip", config.ArchiveFileType.ZIP),
    (".7z", config.ArchiveFileType.SEVENZIP),
    (".rar", config.ArchiveFileType.RAR),
])
def test_a_type_is_resolved_from_the_extension(extension, expected):
    assert archive.get_archive_type(f"file{extension}") == expected


def test_an_unknown_extension_resolves_to_nothing():
    assert archive.get_archive_type("notes.txt") is None


###########################################################
# Capability flags
###########################################################

def test_zip_and_sevenzip_can_be_created():
    assert archive.is_creatable_archive_type(config.ArchiveFileType.ZIP) is True
    assert archive.is_creatable_archive_type(config.ArchiveFileType.SEVENZIP) is True


def test_rar_cannot_be_created():
    # No free RAR compressor, so creation is deliberately not offered.
    assert archive.is_creatable_archive_type(config.ArchiveFileType.RAR) is False


def test_everything_creatable_is_also_extractable():
    for archive_type in config.ArchiveFileType.members():
        if archive.is_creatable_archive_type(archive_type):
            assert archive.is_extractable_archive_type(archive_type) is True, \
                f"{archive_type} can be created but not extracted"


@pytest.mark.parametrize("archive_type", [
    config.ArchiveFileType.ZIP,
    config.ArchiveFileType.SEVENZIP,
    config.ArchiveFileType.RAR,
    config.ArchiveFileType.ISO,
    config.ArchiveFileType.EXE,
])
def test_the_extractable_types_are_extractable(archive_type):
    assert archive.is_extractable_archive_type(archive_type) is True


###########################################################
# Known archive matching
###########################################################

def test_an_extension_match_does_not_need_the_file_to_exist():
    # Extensions are checked before the file is touched.
    assert archive.is_known_archive("absent.zip", extensions = [".zip"]) is True


def test_a_mime_match_needs_a_real_file(tmp_path):
    assert archive.is_known_archive(
        str(tmp_path / "absent.bin"), mime_types = ["application/zip"]) is False


def test_no_criteria_matches_nothing():
    assert archive.is_known_archive("file.zip") is False
