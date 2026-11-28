# Imports
import pytest

# Local imports
from joybox import archiveinfo, config


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
    ("is_lzh_archive", config.ArchiveLzhFileType),
    ("is_stuffit_archive", config.ArchiveStuffItFileType),
    ("is_tarball_archive", config.ArchiveTarballFileType),
    ("is_disc_archive", config.ArchiveDiscFileType),
]


@pytest.mark.parametrize("detector,enum_class", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_each_detector_recognises_its_own_extensions(detector, enum_class):
    check = getattr(archiveinfo, detector)

    missed = [extension for extension in enum_class.cvalues() if check(f"file{extension}") is not True]

    assert not missed, f"{detector} missed {missed}"


@pytest.mark.parametrize("detector,enum_class", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_each_detector_is_case_insensitive(detector, enum_class):
    check = getattr(archiveinfo, detector)

    missed = [extension for extension in enum_class.cvalues() if check(f"file{extension.upper()}") is not True]

    assert not missed, f"{detector} missed {missed}"


@pytest.mark.parametrize("detector,_enum", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_no_detector_claims_a_plain_file(detector, _enum):
    assert getattr(archiveinfo, detector)("notes.txt") is False


@pytest.mark.parametrize("detector,enum_class", DETECTORS, ids = [d for d, _ in DETECTORS])
def test_every_archive_type_is_an_archive(detector, enum_class):
    # is_archive has to cover every type the codebase can extract.
    missed = [extension for extension in enum_class.cvalues() if archiveinfo.is_archive(f"file{extension}") is not True]

    assert not missed, f"is_archive does not recognise {missed}"


def test_rar_counts_as_an_archive():
    # RAR is extractable and has its own detector, so it belongs in is_archive.
    assert archiveinfo.is_archive("file.rar") is True
    assert archiveinfo.is_extractable_archive_type(config.ArchiveFileType.RAR) is True


def test_executables_and_appimages_count_as_archives():
    assert archiveinfo.is_archive("setup.exe") is True
    assert archiveinfo.is_archive("app.AppImage") is True


def test_a_plain_file_is_not_an_archive():
    assert archiveinfo.is_archive("notes.txt") is False


def test_a_tarball_compound_extension_is_recognised():
    # ".tar.gz" must match as a unit, not as ".gz".
    assert archiveinfo.is_tarball_archive("backup.tar.gz") is True


###########################################################
# Archive type resolution
###########################################################

@pytest.mark.parametrize("extension,expected", [
    (".zip", config.ArchiveFileType.ZIP),
    (".7z", config.ArchiveFileType.SEVENZIP),
    (".rar", config.ArchiveFileType.RAR),
    (".lzh", config.ArchiveFileType.LZH),
    (".lha", config.ArchiveFileType.LHA),
    (".sit", config.ArchiveFileType.SIT),
])
def test_a_type_is_resolved_from_the_extension(extension, expected):
    assert archiveinfo.get_archive_type(f"file{extension}") == expected


def test_an_unknown_extension_resolves_to_nothing():
    assert archiveinfo.get_archive_type("notes.txt") is None


@pytest.mark.parametrize("mime_type,expected", [
    ("application/zip", config.ArchiveFileType.ZIP),
    ("application/x-7z-compressed", config.ArchiveFileType.SEVENZIP),
    ("application/x-rar-compressed", config.ArchiveFileType.RAR),
    ("application/x-lzh-compressed", config.ArchiveFileType.LZH),
    ("application/x-stuffit", config.ArchiveFileType.SIT),
    ("application/gzip", config.ArchiveFileType.TAR_GZ),
    ("application/x-iso9660-image", config.ArchiveFileType.ISO),
    ("text/plain", None),
])
def test_a_file_without_an_extension_is_typed_by_its_content(tmp_path, monkeypatch, mime_type, expected):
    source = tmp_path / "download"
    source.write_bytes(b"data")
    monkeypatch.setattr(archiveinfo.paths, "get_file_mime_type", lambda path: mime_type)

    assert archiveinfo.get_archive_type(str(source)) == expected


###########################################################
# Capability flags
###########################################################

def test_zip_and_sevenzip_can_be_created():
    assert archiveinfo.is_creatable_archive_type(config.ArchiveFileType.ZIP) is True
    assert archiveinfo.is_creatable_archive_type(config.ArchiveFileType.SEVENZIP) is True


def test_rar_cannot_be_created():
    # No free RAR compressor, so creation is deliberately not offered.
    assert archiveinfo.is_creatable_archive_type(config.ArchiveFileType.RAR) is False


def test_everything_creatable_is_also_extractable():
    creatable = [
        archive_type for archive_type in config.ArchiveFileType.members()
        if archiveinfo.is_creatable_archive_type(archive_type)]
    unextractable = [
        archive_type for archive_type in creatable if archiveinfo.is_extractable_archive_type(archive_type) is not True]

    assert creatable
    assert not unextractable, f"{unextractable} can be created but not extracted"


@pytest.mark.parametrize("archive_type", [
    config.ArchiveFileType.ZIP,
    config.ArchiveFileType.SEVENZIP,
    config.ArchiveFileType.RAR,
    config.ArchiveFileType.LZH,
    config.ArchiveFileType.SIT,
    config.ArchiveFileType.ISO,
    config.ArchiveFileType.EXE,
])
def test_the_extractable_types_are_extractable(archive_type):
    assert archiveinfo.is_extractable_archive_type(archive_type) is True


def test_an_appimage_is_neither_creatable_nor_extractable():
    assert not archiveinfo.is_creatable_archive_type(config.ArchiveFileType.APPIMAGE)
    assert not archiveinfo.is_extractable_archive_type(config.ArchiveFileType.APPIMAGE)


###########################################################
# Known archive matching
###########################################################

def test_an_extension_match_does_not_need_the_file_to_exist():
    # Extensions are checked before the file is touched.
    assert archiveinfo.is_known_archive("absent.zip", extensions = [".zip"]) is True


def test_a_mime_match_needs_a_real_file(tmp_path):
    assert archiveinfo.is_known_archive(
        str(tmp_path / "absent.bin"), mime_types = ["application/zip"]) is False


def test_a_matching_mime_type_identifies_a_real_file(tmp_path, monkeypatch):
    source = tmp_path / "download"
    source.write_bytes(b"data")
    monkeypatch.setattr(archiveinfo.paths, "get_file_mime_type", lambda path: "Application/ZIP")

    assert archiveinfo.is_known_archive(str(source), mime_types = ["application/zip"])


def test_no_criteria_matches_nothing():
    assert archiveinfo.is_known_archive("file.zip") is False


###########################################################
# Archive checksums
###########################################################

def test_each_entry_in_a_zip_carries_its_crc(tmp_path):
    import zipfile

    target = tmp_path / "Game.zip"
    with zipfile.ZipFile(str(target), "w") as handle:
        handle.writestr("first.txt", "first")
        handle.writestr("nested/second.txt", "second")

    checksums = archiveinfo.get_archive_checksums(str(target))

    assert sorted(entry["path"] for entry in checksums) == ["first.txt", "nested/second.txt"]
    assert all(len(entry["crc"]) == 8 for entry in checksums)


def test_directory_entries_are_not_checksummed(tmp_path):
    import zipfile

    target = tmp_path / "Game.zip"
    with zipfile.ZipFile(str(target), "w") as handle:
        handle.writestr("nested/", "")
        handle.writestr("nested/file.txt", "data")

    assert [entry["path"] for entry in archiveinfo.get_archive_checksums(str(target))] == \
        ["nested/file.txt"]


def test_a_non_zip_archive_has_no_checksums(tmp_path):
    target = tmp_path / "Game.7z"
    target.write_text("not really a 7z")

    assert archiveinfo.get_archive_checksums(str(target)) == []


def test_a_missing_archive_has_no_checksums(tmp_path):
    assert archiveinfo.get_archive_checksums(str(tmp_path / "absent.zip")) == []
