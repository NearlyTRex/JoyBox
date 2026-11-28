# Imports
import pytest

# Local imports
from joybox import archive, config


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

    assert archive.check_archive_compression_output_files(str(target), None) is True


def test_a_missing_archive_is_a_failure(tmp_path):
    assert archive.check_archive_compression_output_files(
        str(tmp_path / "absent.7z"), None) is False


def test_every_volume_is_checked_for(tmp_path):
    target = tmp_path / "Game.7z"
    for index in [1, 2, 3]:
        (tmp_path / ("Game.7z.%03d" % index)).write_text("volume")

    assert archive.check_archive_compression_output_files(str(target), "4g") is True


def test_a_split_archive_with_no_volumes_is_a_failure(tmp_path):
    assert archive.check_archive_compression_output_files(
        str(tmp_path / "Game.7z"), "4g") is False


def test_volumes_are_searched_up_to_the_last_numbered_one(monkeypatch):
    seen = []
    monkeypatch.setattr(archive.os.path, "exists", lambda path: seen.append(path) or True)

    assert archive.check_archive_compression_output_files("/out/Game.7z", "1g")
    assert "/out/Game.7z.998" in seen
    assert "/out/Game.7z.999" not in seen


def test_a_lone_volume_loses_its_numbering(tmp_path):
    # Splitting that produced one part is not a split archive, and the .001
    # suffix would make every reader look for a second part.
    target = tmp_path / "Game.7z"
    (tmp_path / "Game.7z.001").write_text("volume")

    assert archive.check_archive_compression_output_files(str(target), "4g") is True
    assert target.is_file()
    assert not (tmp_path / "Game.7z.001").exists()


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
    "Unar": "/tools/unar",
}


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(archive.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(archive.programs, "get_tool_program", TOOL_PATHS.get)
    monkeypatch.setattr(
        archive.sandboxpaths, "translate_path_if_necessary",
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

    removed = []
    monkeypatch.setattr(archive.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    assert archive.create_archive_from_file("/out/Game.7z", "/in/Game.iso", delete_original = True) is False
    assert removed == []


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


def test_archiving_a_folder_runs_inside_it(installed, recording_command, existing_output, tmp_path):
    source = tmp_path / "Game"
    source.mkdir()

    assert archive.create_archive_from_folder("/out/Game.zip", str(source)) is True
    assert recording_command.options().get_cwd() == str(source)
    assert "-tzip" in recording_command.only()


@pytest.mark.parametrize("archive_file", ["/out/Game.rar", "/out/Game.unknown"])
def test_archiving_a_folder_to_an_uncreatable_type_is_refused(installed, recording_command, tmp_path, archive_file):
    assert archive.create_archive_from_folder(archive_file, str(tmp_path)) is False
    assert recording_command.ran() is False


def test_archiving_a_folder_without_the_tool_reports_failure(missing, recording_command, tmp_path):
    assert archive.create_archive_from_folder("/out/Game.7z", str(tmp_path)) is False
    assert recording_command.ran() is False


def test_a_failed_folder_archive_keeps_the_folder(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert archive.create_archive_from_folder("/out/Game.7z", str(tmp_path), delete_original = True) is False
    assert tmp_path.exists()


def test_archiving_a_folder_can_remove_it(installed, recording_command, existing_output, monkeypatch, tmp_path):
    removed = []
    monkeypatch.setattr(archive.fileops, "remove_directory", lambda src, **kwargs: removed.append(src))

    archive.create_archive_from_folder("/out/Game.7z", str(tmp_path), delete_original = True)

    assert removed == [str(tmp_path)]


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


def test_a_stuffit_is_extracted_with_unar(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.sit", "/out")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/unar"
    assert cmd[-1] == "/in/Game.sit"
    assert recording_command.value_after("-o") == "/out"


def test_unar_does_not_wrap_the_contents_in_a_folder(installed, recording_command, existing_output):
    # Without -D unar adds its own folder when the archive holds several items,
    # so the files would land one level deeper than with every other format.
    archive.extract_archive("/in/Game.sit", "/out")

    assert "-D" in recording_command.only()


def test_unar_takes_a_password_when_given_one(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.sit", "/out", password = "example")

    assert recording_command.value_after("-p") == "example"


def test_unar_overwrites_by_default(installed, recording_command, existing_output):
    # Without -f or -s unar asks what to do with each existing file and the run hangs.
    archive.extract_archive("/in/Game.sit", "/out")
    cmd = recording_command.only()

    assert "-f" in cmd
    assert "-s" not in cmd


def test_unar_can_keep_what_is_already_there(installed, recording_command, existing_output):
    archive.extract_archive("/in/Game.sit", "/out", skip_existing = True)
    cmd = recording_command.only()

    assert "-s" in cmd
    assert "-f" not in cmd


def test_an_lzh_is_extracted_with_sevenzip(installed, recording_command, existing_output, monkeypatch):
    monkeypatch.setattr(archive.fileops, "decode_legacy_filenames", lambda **kwargs: True)
    archive.extract_archive("/in/Game.lzh", "/out")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/7z"
    assert "-o/out" in cmd


def test_an_lzh_has_its_names_decoded_from_shift_jis(installed, recording_command, existing_output, monkeypatch):
    # LZH archives store names in the packer's code page, which for the
    # Japanese games they mostly hold is Shift-JIS.
    decoded = []
    monkeypatch.setattr(archive.fileops, "decode_legacy_filenames", lambda **kwargs: decoded.append(kwargs) or True)

    assert archive.extract_archive("/in/Game.lzh", "/out") is True
    assert [(d["src"], d["encoding"]) for d in decoded] == [("/out", "cp932")]


def test_other_archives_keep_their_names(installed, recording_command, existing_output, monkeypatch):
    decoded = []
    monkeypatch.setattr(archive.fileops, "decode_legacy_filenames", lambda **kwargs: decoded.append(kwargs) or True)

    archive.extract_archive("/in/Game.7z", "/out")

    assert decoded == []


def test_a_failed_name_decode_reports_failure(installed, recording_command, existing_output, monkeypatch):
    monkeypatch.setattr(archive.fileops, "decode_legacy_filenames", lambda **kwargs: False)

    assert archive.extract_archive("/in/Game.lzh", "/out") is False


def test_extracting_without_the_tool_reports_failure(missing, recording_command):
    assert archive.extract_archive("/in/Game.7z", "/out") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("archive_file,tool", [
    ("/in/Game.tar.gz", "Tar"),
    ("/in/Game.rar", "Unrar"),
    ("/in/Game.sit", "Unar"),
])
def test_extracting_without_the_format_tool_reports_failure(monkeypatch, recording_command, archive_file, tool):
    # 7-Zip alone does not stand in for the tool a tarball or rar needs.
    monkeypatch.setattr(archive.programs, "is_tool_installed", lambda name: name != tool)
    monkeypatch.setattr(archive.programs, "get_tool_program", lambda name: "/tools/7z")

    assert archive.extract_archive(archive_file, "/out") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("archive_file", ["/in/Game.unknown", "/in/Game.AppImage"])
def test_extracting_an_unextractable_type_is_refused(installed, recording_command, archive_file):
    assert archive.extract_archive(archive_file, "/out") is False
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


def test_a_directory_entry_without_its_flag_folds_into_its_contents(installed, monkeypatch):
    listing_command(monkeypatch, "\n".join([
        "2024-01-01 12:00:00 .....            0            0  nested",
        "2024-01-01 12:00:00 ....A          100           50  nested/file.txt",
    ]))

    assert archive.list_archive("/in/Game.7z") == ["nested/file.txt"]


def test_listing_decodes_byte_output(installed, monkeypatch):
    listing_command(monkeypatch, LISTING.encode())

    assert "top.txt" in archive.list_archive("/in/Game.7z")


def test_a_banner_line_is_not_mistaken_for_a_file(installed, monkeypatch):
    listing_command(monkeypatch, "7-Zip 23.01\nScanning the drive for archives")

    assert archive.list_archive("/in/Game.7z") == []


def test_listing_without_the_tool_yields_nothing(missing, recording_command):
    assert archive.list_archive("/in/Game.7z") == []
    assert recording_command.ran() is False


def test_a_listing_is_parsed_into_its_file_paths():
    assert archive.parse_archive_listing(LISTING) == ["nested/file.txt", "top.txt"]


###########################################################
# Archive type checks
###########################################################

def test_a_creatable_archive_type_is_returned():
    assert archive.get_creatable_archive_type("/out/Game.7z") == config.ArchiveFileType.SEVENZIP


@pytest.mark.parametrize("archive_file", ["/out/Game.rar", "/out/Game.unknown"])
def test_an_uncreatable_archive_type_is_none(archive_file):
    assert archive.get_creatable_archive_type(archive_file) is None


def test_a_known_archive_is_extractable():
    assert archive.is_extractable_archive("/in/Game.rar") is True


def test_an_unknown_archive_is_not_extractable():
    assert archive.is_extractable_archive("/in/Game.unknown") is False


@pytest.mark.parametrize(("path", "file_types", "expected"), [
    ("/in/Game.iso", ".iso,.bin", True),
    ("/in/Game.bin", ".iso,.bin", True),
    ("/in/Game.cue", ".iso,.bin", False),
    ("/in/Game.cue", "", True),
])
def test_a_path_is_matched_against_the_listed_file_types(path, file_types, expected):
    assert archive.has_listed_file_type(path, file_types) is expected


###########################################################
# Rezipping
###########################################################

def test_a_zip_is_extracted_then_rezipped_in_place(monkeypatch):
    calls = []
    monkeypatch.setattr(archive, "extract_archive", lambda **kwargs: calls.append(("extract", kwargs)) or True)
    monkeypatch.setattr(archive, "create_archive_from_folder", lambda **kwargs: calls.append(("create", kwargs)) or True)

    archive.rezip_archive("/in/Game.zip")

    assert [(name, kwargs["archive_file"]) for name, kwargs in calls] == [
        ("extract", "/in/Game.zip"), ("create", "/in/Game.zip")]
    assert calls[0][1]["extract_dir"] == calls[1][1]["source_dir"] == "/in/Game_extracted"
