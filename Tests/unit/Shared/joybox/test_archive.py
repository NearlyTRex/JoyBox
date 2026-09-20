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


###########################################################
# Compression flags
#
# The flags decide what the archive is and whether it can be rebuilt byte for
# byte later. A format flag that does not match the file extension produces an
# archive nothing will open by name.
###########################################################

def flags(archive_type, password = None, volume_size = None):
    return archive.get_archive_compression_flags(archive_type, password, volume_size)


def test_a_zip_is_built_as_a_zip():
    assert "-tzip" in flags(config.ArchiveFileType.ZIP)


def test_a_sevenzip_is_built_as_a_sevenzip():
    assert "-t7z" in flags(config.ArchiveFileType.SEVENZIP)


def test_the_two_formats_do_not_share_a_format_flag():
    assert "-t7z" not in flags(config.ArchiveFileType.ZIP)
    assert "-tzip" not in flags(config.ArchiveFileType.SEVENZIP)


@pytest.mark.parametrize("archive_type", [
    config.ArchiveFileType.ZIP,
    config.ArchiveFileType.SEVENZIP,
])
def test_an_archive_is_reproducible(archive_type):
    # The collection hashes its archives, so two runs over the same files have
    # to produce the same bytes; timestamps and ordering are what break that.
    built = flags(archive_type)

    assert "-ma=1" in built
    assert "-mtc=off" in built


@pytest.mark.parametrize("archive_type", [
    config.ArchiveFileType.ZIP,
    config.ArchiveFileType.SEVENZIP,
])
def test_a_password_is_passed_when_given(archive_type):
    assert "-pexample" in flags(archive_type, password = "example")


@pytest.mark.parametrize("archive_type", [
    config.ArchiveFileType.ZIP,
    config.ArchiveFileType.SEVENZIP,
])
def test_no_password_flag_is_added_without_one(archive_type):
    built = flags(archive_type)

    assert not any(flag.startswith("-p") for flag in built)


@pytest.mark.parametrize("password", [None, "", 12345])
def test_an_unusable_password_is_ignored(password):
    built = flags(config.ArchiveFileType.ZIP, password = password)

    assert not any(flag.startswith("-p") for flag in built)


def test_a_volume_size_splits_the_archive():
    assert "-v4g" in flags(config.ArchiveFileType.ZIP, volume_size = "4g")


@pytest.mark.parametrize("volume_size", [None, "", 4096])
def test_an_unusable_volume_size_is_ignored(volume_size):
    built = flags(config.ArchiveFileType.ZIP, volume_size = volume_size)

    assert not any(flag.startswith("-v") for flag in built)


def test_an_unsupported_type_gets_only_the_general_flags():
    assert flags(config.ArchiveFileType.RAR) == []


###########################################################
# Output files
###########################################################

def test_a_single_archive_is_checked_for(tmp_path):
    target = tmp_path / "Game.7z"
    target.write_text("archive")

    assert archive.check_archive_compression_output_files(str(target), None, None) is True


def test_a_missing_archive_is_a_failure(tmp_path):
    assert archive.check_archive_compression_output_files(
        str(tmp_path / "absent.7z"), None, None) is False


def test_every_volume_is_checked_for(tmp_path):
    target = tmp_path / "Game.7z"
    for index in [1, 2, 3]:
        (tmp_path / ("Game.7z.%03d" % index)).write_text("volume")

    assert archive.check_archive_compression_output_files(str(target), None, "4g") is True


def test_a_split_archive_with_no_volumes_is_a_failure(tmp_path):
    assert archive.check_archive_compression_output_files(
        str(tmp_path / "Game.7z"), None, "4g") is False


def test_a_lone_volume_loses_its_numbering(tmp_path):
    # Splitting that produced one part is not a split archive, and the .001
    # suffix would make every reader look for a second part.
    target = tmp_path / "Game.7z"
    (tmp_path / "Game.7z.001").write_text("volume")

    assert archive.check_archive_compression_output_files(str(target), None, "4g") is True
    assert target.is_file()
    assert not (tmp_path / "Game.7z.001").exists()


###########################################################
# Archive checksums
###########################################################

def test_each_entry_in_a_zip_carries_its_crc(tmp_path):
    import zipfile

    target = tmp_path / "Game.zip"
    with zipfile.ZipFile(str(target), "w") as handle:
        handle.writestr("first.txt", "first")
        handle.writestr("nested/second.txt", "second")

    checksums = archive.get_archive_checksums(str(target))

    assert sorted(entry["path"] for entry in checksums) == ["first.txt", "nested/second.txt"]
    assert all(len(entry["crc"]) == 8 for entry in checksums)


def test_directory_entries_are_not_checksummed(tmp_path):
    import zipfile

    target = tmp_path / "Game.zip"
    with zipfile.ZipFile(str(target), "w") as handle:
        handle.writestr("nested/", "")
        handle.writestr("nested/file.txt", "data")

    assert [entry["path"] for entry in archive.get_archive_checksums(str(target))] == \
        ["nested/file.txt"]


def test_a_non_zip_archive_has_no_checksums(tmp_path):
    target = tmp_path / "Game.7z"
    target.write_text("not really a 7z")

    assert archive.get_archive_checksums(str(target)) == []


def test_a_missing_archive_has_no_checksums(tmp_path):
    assert archive.get_archive_checksums(str(tmp_path / "absent.zip")) == []


###########################################################
# Tool wrappers
#
# 7-Zip, tar and unrar each take their arguments differently, and the wrong
# extraction flag either overwrites files the caller asked to keep or leaves
# them where they were.
###########################################################

TOOL_PATHS = {
    "7-Zip": "/tools/7z",
    "Tar": "/tools/tar",
    "Unrar": "/tools/unrar",
}


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(archive.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(archive.programs, "get_tool_program", lambda name: TOOL_PATHS.get(name))
    monkeypatch.setattr(
        archive.sandbox, "translate_path_if_necessary",
        lambda path, program_exe, program_name: path)
    return TOOL_PATHS


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(archive.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(archive.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(archive.os.path, "exists", lambda path: True)
    monkeypatch.setattr(archive.paths, "is_directory_empty", lambda path: False)


def test_creating_an_archive_adds_the_source(installed, recording_command, existing_output):
    archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/7z"
    assert cmd[1] == "a"
    assert cmd[-2:] == ["/out/Game.7z", "/in/Game.iso"]


def test_creating_an_archive_runs_beside_the_source(installed, recording_command, existing_output):
    # 7-Zip stores paths relative to the working directory, so running
    # elsewhere buries the whole host path inside the archive.
    archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso")

    assert recording_command.options().get_cwd() == "/in"


def test_creating_an_archive_uses_the_flags_for_its_extension(installed, recording_command, existing_output):
    archive.create_archive_from_file("/out/Game.zip", "/in/Game.iso")

    assert "-tzip" in recording_command.only()


def test_an_archive_type_that_cannot_be_created_is_refused(installed, recording_command):
    assert archive.create_archive_from_file("/out/Game.rar", "/in/Game.iso") is False
    assert recording_command.ran() is False


def test_an_unrecognised_archive_name_is_refused(installed, recording_command):
    assert archive.create_archive_from_file("/out/Game.unknown", "/in/Game.iso") is False
    assert recording_command.ran() is False


def test_creating_an_archive_without_the_tool_reports_failure(missing, recording_command):
    assert archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso") is False
    assert recording_command.ran() is False


def test_a_failed_creation_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso") is False


def test_creating_an_archive_can_remove_the_source(installed, recording_command, existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(archive.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso", delete_original = True)

    assert removed == ["/in/Game.iso"]


def test_a_failed_creation_keeps_the_source(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must survive a failed archive")

    monkeypatch.setattr(archive.fileops, "remove_file", fail)

    archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso", delete_original = True)


def test_archiving_a_folder_adds_each_member(installed, recording_command, existing_output, tmp_path):
    source = tmp_path / "Game"
    source.mkdir()
    (source / "data.bin").write_text("data")
    (source / "readme.txt").write_text("notes")

    archive.create_archive_from_folder("/out/Game.7z", str(source))
    cmd = recording_command.only()

    assert str(source / "data.bin") in cmd
    assert str(source / "readme.txt") in cmd


def test_archiving_a_folder_skips_what_was_excluded(installed, recording_command, existing_output, tmp_path):
    source = tmp_path / "Game"
    source.mkdir()
    (source / "data.bin").write_text("data")
    (source / "skip.log").write_text("noise")

    archive.create_archive_from_folder("/out/Game.7z", str(source), excludes = ["skip.log"])
    cmd = recording_command.only()

    assert str(source / "data.bin") in cmd
    assert str(source / "skip.log") not in cmd


def test_extracting_names_the_destination(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.7z", "/out")

    assert "-o/out" in recording_command.only()


def test_extracting_overwrites_by_default(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.7z", "/out")

    assert "-aoa" in recording_command.only()


def test_extracting_can_keep_what_is_already_there(installed, recording_command, existing_output):
    # Resuming an interrupted extraction must not undo the files that made it.
    archive.extract_archive("/in/Game.7z", "/out", skip_existing = True)
    cmd = recording_command.only()

    assert "-aos" in cmd
    assert "-aoa" not in cmd


def test_extracting_passes_a_password(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.7z", "/out", password = "example")

    assert "-pexample" in recording_command.only()


def test_a_tarball_is_extracted_with_tar(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.tar.gz", "/out")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/tar"
    assert recording_command.value_after("-C") == "/out"


def test_a_rar_is_extracted_with_unrar(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.rar", "/out")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/unrar"
    assert cmd[1] == "x"


def test_unrar_is_told_not_to_prompt_for_a_password(installed, recording_command, existing_output):
    # Without this unrar stops for input on an encrypted archive and the run
    # hangs rather than failing.
    archive.extract_archive("/in/Game.rar", "/out")

    assert "-p-" in recording_command.only()


def test_unrar_takes_a_password_when_given_one(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.rar", "/out", password = "example")
    cmd = recording_command.only()

    assert "-pexample" in cmd
    assert "-p-" not in cmd


def test_unrar_overwrites_by_default(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.rar", "/out")

    assert "-o+" in recording_command.only()


def test_unrar_can_keep_what_is_already_there(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.rar", "/out", skip_existing = True)

    assert "-o-" in recording_command.only()


def test_extracting_without_the_tool_reports_failure(missing, recording_command):
    assert archive.extract_archive("/in/Game.7z", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_extraction_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert archive.extract_archive("/in/Game.7z", "/out") is False


def test_an_extraction_that_produced_nothing_reports_failure(installed, recording_command, monkeypatch):
    monkeypatch.setattr(archive.os.path, "exists", lambda path: True)
    monkeypatch.setattr(archive.paths, "is_directory_empty", lambda path: True)

    assert archive.extract_archive("/in/Game.7z", "/out") is False


def test_extracting_can_remove_the_archive(installed, recording_command, existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(archive.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    archive.extract_archive("/in/Game.7z", "/out", delete_original = True)

    assert removed == ["/in/Game.7z"]


def test_testing_an_archive_uses_the_test_mode(installed, recording_command):
    assert archive.test_archive("/in/Game.7z") is True
    assert recording_command.only() == ["/tools/7z", "t", "/in/Game.7z"]


def test_a_broken_archive_fails_its_test(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 2)

    assert archive.test_archive("/in/Game.7z") is False


def test_testing_without_the_tool_reports_failure(missing, recording_command):
    assert archive.test_archive("/in/Game.7z") is False
    assert recording_command.ran() is False


###########################################################
# Listing an archive
###########################################################

LISTING = "\n".join([
    "   Date      Time    Attr         Size   Compressed  Name",
    "------------------- ----- ------------ ------------  ------------------------",
    "2024-01-01 12:00:00 D....            0            0  nested",
    "2024-01-01 12:00:00 ....A          100           50  nested/file.txt",
    "2024-01-01 12:00:00 ....A          200           80  top.txt",
    "------------------- ----- ------------ ------------  ------------------------",
])


def listing_command(monkeypatch, output):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, output = output)


def test_every_file_in_the_listing_is_returned(installed, monkeypatch):
    listing_command(monkeypatch, LISTING)

    assert sorted(archive.list_archive("/in/Game.7z")) == ["nested/file.txt", "top.txt"]


def test_a_directory_entry_is_not_listed_as_a_file(installed, monkeypatch):
    # A directory listed alongside its contents would be extracted twice.
    listing_command(monkeypatch, LISTING)

    assert "nested" not in archive.list_archive("/in/Game.7z")


def test_an_empty_directory_keeps_its_own_entry(installed, monkeypatch):
    listing_command(monkeypatch, "\n".join([
        "2024-01-01 12:00:00 ....A          100           50  alone.txt",
    ]))

    assert archive.list_archive("/in/Game.7z") == ["alone.txt"]


def test_listing_decodes_byte_output(installed, monkeypatch):
    listing_command(monkeypatch, LISTING.encode())

    assert "top.txt" in archive.list_archive("/in/Game.7z")


def test_a_banner_line_is_not_mistaken_for_a_file(installed, monkeypatch):
    listing_command(monkeypatch, "7-Zip 23.01\nScanning the drive for archives")

    assert archive.list_archive("/in/Game.7z") == []


def test_listing_without_the_tool_yields_nothing(missing, recording_command):
    assert archive.list_archive("/in/Game.7z") == []
    assert recording_command.ran() is False
