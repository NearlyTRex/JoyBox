# Imports
import pytest

# Local imports
from joybox import chd


###########################################################
# CHD wrappers
#
# Each of these builds a chdman argument list. A wrong flag or a swapped input
# and output silently produces the wrong artifact, so the command is what gets
# pinned here; the real round trip lives in the integration suite.
###########################################################

@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(chd.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(chd.programs, "get_tool_program", lambda name: "/tools/chdman")
    return "/tools/chdman"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(chd.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(chd.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    # The wrappers confirm the artifact landed before reporting success.
    monkeypatch.setattr(chd.os.path, "exists", lambda path: True)


###########################################################
# Companion paths
###########################################################

def test_the_iso_beside_a_chd_swaps_the_extension():
    assert chd.get_disc_iso("/games/Game.chd") == "/games/Game.iso"


def test_the_toc_beside_a_chd_swaps_the_extension():
    assert chd.get_disc_toc("/games/Game.chd") == "/games/Game.toc"


@pytest.mark.parametrize("accessor", [chd.get_disc_iso, chd.get_disc_toc])
def test_the_companion_paths_stay_in_the_same_directory(accessor):
    assert accessor("/games/psx/Game.chd").startswith("/games/psx/")


def test_the_companion_paths_differ():
    assert chd.get_disc_iso("/games/Game.chd") != chd.get_disc_toc("/games/Game.chd")


def test_a_name_with_spaces_keeps_its_spaces():
    assert chd.get_disc_iso("/games/Final Fantasy VII.chd") == \
        "/games/Final Fantasy VII.iso"


###########################################################
# Creating
###########################################################

def test_creating_invokes_createcd(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.only()[:2] == ["/tools/chdman", "createcd"]


def test_creating_passes_the_source_as_input(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.value_after("-i") == "/in/Game.iso"


def test_creating_passes_the_target_as_output(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.value_after("-o") == "/out/Game.chd"


def test_creating_does_not_swap_input_and_output(installed, recording_command, existing_output):
    # Swapped, chdman would overwrite the source with a compressed empty image.
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.value_after("-i") != recording_command.value_after("-o")


def test_creating_blocks_on_the_tool(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert "/tools/chdman" in recording_command.options().get_blocking_processes()


def test_creating_declares_its_output_path(installed, recording_command, existing_output):
    # The output path guard is what removes a partial file on interruption.
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert "/out/Game.chd" in recording_command.options().get_output_paths()


def test_creating_without_the_tool_reports_failure(missing, recording_command):
    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso") is False
    assert recording_command.ran() is False


def test_a_failed_create_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso") is False


def test_a_failed_create_does_not_delete_the_source(installed, monkeypatch):
    # Deleting the original after a failure loses the only copy.
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must not be removed after a failure")

    monkeypatch.setattr(chd.fileops, "remove_file", fail)

    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", delete_original = True) is False


def test_a_successful_create_deletes_the_source_when_asked(installed, recording_command,
                                                           existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(
        chd.fileops, "remove_file", lambda src, **kwargs: removed.append(src))
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", delete_original = True)

    assert removed == ["/in/Game.iso"]


def test_the_source_is_kept_by_default(installed, recording_command, existing_output,
                                       monkeypatch):
    removed = []
    monkeypatch.setattr(chd.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso") is True
    assert removed == []


###########################################################
# Extracting
###########################################################

def test_extracting_invokes_extractcd(installed, recording_command, existing_output):
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert recording_command.only()[:2] == ["/tools/chdman", "extractcd"]


def test_extracting_passes_the_chd_as_input(installed, recording_command, existing_output):
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert recording_command.value_after("-i") == "/in/Game.chd"


def test_extracting_names_both_outputs(installed, recording_command, existing_output):
    # The toc and the binary are separate outputs; chdman needs both named.
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert recording_command.value_after("-o") == "/out/Game.toc"
    assert recording_command.value_after("-ob") == "/out/Game.bin"


def test_extracting_without_the_tool_reports_failure(missing, recording_command):
    assert chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc") is False


###########################################################
# Verifying
###########################################################

def test_verifying_invokes_verify(installed, recording_command, existing_output):
    chd.verify_disc_chd("/in/Game.chd")

    assert recording_command.only()[:2] == ["/tools/chdman", "verify"]


def test_verifying_passes_the_chd_as_input(installed, recording_command, existing_output):
    chd.verify_disc_chd("/in/Game.chd")

    assert recording_command.value_after("-i") == "/in/Game.chd"


def test_verifying_without_the_tool_reports_failure(missing, recording_command):
    assert chd.verify_disc_chd("/in/Game.chd") is False


###########################################################
# Pretending
###########################################################

@pytest.mark.parametrize("call", [
    lambda: chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", pretend_run = True),
    lambda: chd.extract_disc_chd("/in/Game.chd", "/o/Game.bin", "/o/Game.toc", pretend_run = True),
    lambda: chd.verify_disc_chd("/in/Game.chd", pretend_run = True),
])
def test_pretending_still_builds_the_command(installed, recording_command, existing_output, call):
    # The command has to be built so a pretend run can print what it would do.
    call()

    assert recording_command.ran() is True
    assert recording_command.calls[0]["kwargs"].get("pretend_run") is True

@pytest.mark.parametrize("call", [
    lambda: chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", pretend_run = True),
    lambda: chd.extract_disc_chd("/in/Game.chd", "/o/Game.bin", "/o/Game.toc", pretend_run = True),
])
def test_pretending_reports_success_without_an_output(installed, recording_command, call):
    # Nothing is written, so the output check alone would call every pretend run a failure.
    assert call() is True



###########################################################
# Extract cleanup and verify output
###########################################################

def test_extracting_with_force_overwrite_passes_force(installed, recording_command,
                                                       existing_output):
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc", force_overwrite = True)

    assert recording_command.only()[-1] == "--force"


def test_extracting_without_force_overwrite_omits_force(installed, recording_command,
                                                         existing_output):
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert "--force" not in recording_command.only()


def test_a_failed_extract_reports_failure_and_keeps_the_chd(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    removed = []
    monkeypatch.setattr(chd.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    assert chd.extract_disc_chd(
        "/in/Game.chd", "/out/Game.bin", "/out/Game.toc", delete_original = True) is False
    assert removed == []


def test_a_successful_extract_deletes_the_chd_when_asked(installed, recording_command,
                                                         existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(chd.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    assert chd.extract_disc_chd(
        "/in/Game.chd", "/out/Game.bin", "/out/Game.toc", delete_original = True) is True
    assert removed == ["/in/Game.chd"]


def test_extracting_reports_whether_the_binary_landed(installed, recording_command, monkeypatch):
    monkeypatch.setattr(chd.os.path, "exists", lambda path: path != "/out/Game.bin")

    assert chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc") is False


@pytest.mark.parametrize("output", [
    "Overall SHA1 verification successful!\n",
    b"Overall SHA1 verification successful!\n",
])
def test_verifying_accepts_the_success_line_as_text_or_bytes(installed, monkeypatch, output):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = output)

    assert chd.verify_disc_chd("/in/Game.chd") is True


def test_verifying_without_the_success_line_fails(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = b"Error: SHA1 mismatch")

    assert chd.verify_disc_chd("/in/Game.chd") is False


###########################################################
# Mounting, unmounting and archiving
###########################################################

class FakeIso:

    def __init__(self, monkeypatch, mounted = False, mount_ok = True, unmount_ok = True):
        self.mounted = mounted
        self.mount_ok = mount_ok
        self.unmount_ok = unmount_ok
        self.checked = []
        monkeypatch.setattr(chd.iso, "is_iso_mounted", self.is_iso_mounted)
        monkeypatch.setattr(chd.iso, "mount_iso", self.mount_iso)
        monkeypatch.setattr(chd.iso, "unmount_iso", self.unmount_iso)

    def is_iso_mounted(self, iso_file, mount_dir):
        self.checked.append((iso_file, mount_dir))
        return self.mounted

    def mount_iso(self, iso_file, mount_dir, **kwargs):
        if self.mount_ok:
            self.mounted = True
        return self.mount_ok

    def unmount_iso(self, iso_file, mount_dir, **kwargs):
        if self.unmount_ok:
            self.mounted = False
        return self.unmount_ok


def test_mount_state_checks_the_companion_iso(monkeypatch):
    fake = FakeIso(monkeypatch, mounted = True)

    assert chd.is_disc_chd_mounted("/in/Game.chd", "/mnt") is True
    assert fake.checked == [("/in/Game.iso", "/mnt")]


def test_mounting_an_already_mounted_chd_runs_nothing(installed, recording_command, monkeypatch):
    FakeIso(monkeypatch, mounted = True)

    assert chd.mount_disc_chd("/in/Game.chd", "/mnt") is True
    assert recording_command.ran() is False


def test_mounting_extracts_then_mounts_the_iso(installed, recording_command, existing_output,
                                               monkeypatch):
    FakeIso(monkeypatch)

    assert chd.mount_disc_chd("/in/Game.chd", "/mnt") is True
    assert recording_command.value_after("-ob") == "/in/Game.iso"
    assert "--force" in recording_command.only()


def test_mounting_fails_when_extraction_fails(missing, monkeypatch):
    FakeIso(monkeypatch)

    assert chd.mount_disc_chd("/in/Game.chd", "/mnt") is False


def test_mounting_fails_when_the_iso_does_not_mount(installed, recording_command,
                                                     existing_output, monkeypatch):
    FakeIso(monkeypatch, mount_ok = False)

    assert chd.mount_disc_chd("/in/Game.chd", "/mnt") is False


def test_unmounting_an_unmounted_chd_is_a_success(monkeypatch):
    FakeIso(monkeypatch)

    assert chd.unmount_disc_chd("/in/Game.chd", "/mnt") is True


def test_unmounting_a_mounted_chd_unmounts_the_iso(monkeypatch):
    fake = FakeIso(monkeypatch, mounted = True)

    assert chd.unmount_disc_chd("/in/Game.chd", "/mnt") is True
    assert fake.mounted is False


def test_unmounting_reports_a_failed_unmount(monkeypatch):
    FakeIso(monkeypatch, mounted = True, unmount_ok = False)

    assert chd.unmount_disc_chd("/in/Game.chd", "/mnt") is False


@pytest.fixture
def archive_seams(monkeypatch):
    state = {"tmp": (True, "/tmp/chdmount"), "mount": True, "archive": True,
             "removed_files": [], "removed_dirs": [], "archived": []}
    monkeypatch.setattr(chd.fileops, "create_temporary_directory",
                        lambda **kwargs: state["tmp"])
    monkeypatch.setattr(chd, "mount_disc_chd", lambda **kwargs: state["mount"])

    def create_archive_from_folder(archive_file, source_dir, **kwargs):
        state["archived"].append((archive_file, source_dir))
        return state["archive"]

    monkeypatch.setattr(chd.archive, "create_archive_from_folder", create_archive_from_folder)
    monkeypatch.setattr(chd.fileops, "remove_file",
                        lambda src, **kwargs: state["removed_files"].append(src))
    monkeypatch.setattr(chd.fileops, "remove_directory",
                        lambda src, **kwargs: state["removed_dirs"].append(src))
    monkeypatch.setattr(chd.os.path, "exists", lambda path: path == "/out/Game.zip")
    return state


def test_archiving_zips_the_mounted_contents(archive_seams):
    assert chd.archive_disc_chd("/in/Game.chd", "/out/Game.zip") is True
    assert archive_seams["archived"] == [("/out/Game.zip", "/tmp/chdmount")]
    assert archive_seams["removed_dirs"] == ["/tmp/chdmount"]
    assert archive_seams["removed_files"] == []


def test_archiving_deletes_the_chd_when_asked(archive_seams):
    assert chd.archive_disc_chd("/in/Game.chd", "/out/Game.zip", delete_original = True) is True
    assert archive_seams["removed_files"] == ["/in/Game.chd"]


@pytest.mark.parametrize("failure", [
    {"tmp": (False, None)},
    {"mount": False},
    {"archive": False},
])
def test_archiving_stops_at_the_first_failure_and_keeps_the_chd(archive_seams, failure):
    archive_seams.update(failure)

    assert chd.archive_disc_chd("/in/Game.chd", "/out/Game.zip", delete_original = True) is False
    assert archive_seams["removed_files"] == []


###########################################################
# Extracting to ISO
#
# chdman writes CUE/BIN into a temporary folder and bchunk splits it into
# numbered tracks, which are then moved beside the requested iso.
###########################################################

@pytest.fixture
def bchunk(monkeypatch, installed):
    # Stands in for both tools: chdman writes the cue and bin, bchunk the numbered tracks.
    state = {"calls": [], "cue": "  TRACK 01 MODE2/2352\n", "tracks": ["01.iso"], "extracted": True, "returncode": 0}
    def extract_disc_chd(**kwargs):
        state["calls"].append(kwargs)
        if not state["extracted"]:
            return False
        with open(kwargs["toc_file"], "w", encoding = "utf-8") as handle:
            handle.write('FILE "Game.bin" BINARY\n' + state["cue"])
        with open(kwargs["binary_file"], "wb") as handle:
            handle.write(b"binary")
        return True
    def run_returncode_command(cmd, **kwargs):
        state["calls"].append(list(cmd))
        for track in state["tracks"]:
            with open(cmd[3] + track, "wb") as handle:
                handle.write(b"track")
        return state["returncode"]
    monkeypatch.setattr(chd, "extract_disc_chd", extract_disc_chd)
    monkeypatch.setattr(chd.command, "run_returncode_command", run_returncode_command)
    return state


def test_iso_extraction_feeds_the_extracted_cue_and_bin_to_bchunk(tmp_path, bchunk):
    chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso"))

    extracted, bchunk_cmd = bchunk["calls"]
    assert bchunk_cmd[:3] == ["/tools/chdman", extracted["binary_file"], extracted["toc_file"]]
    assert extracted["toc_file"].endswith("Game.cue")


def test_a_single_track_is_named_after_the_iso(tmp_path, bchunk):
    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is True

    assert sorted(path.name for path in tmp_path.iterdir()) == ["Game.iso"]


def test_several_tracks_keep_their_numbered_names(tmp_path, bchunk):
    bchunk["tracks"] = ["01.iso", "02.cdr"]

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is True

    assert sorted(path.name for path in tmp_path.iterdir()) == ["Game01.iso", "Game02.cdr"]


def test_no_tracks_reports_failure(tmp_path, bchunk):
    bchunk["tracks"] = []

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is False


def test_iso_extraction_deletes_the_chd_when_asked(tmp_path, bchunk):
    source = tmp_path / "Game.chd"
    source.write_bytes(b"")

    chd.extract_disc_chd_to_iso(str(source), str(tmp_path / "Game.iso"), delete_original = True)

    assert not source.exists()


@pytest.mark.parametrize("track_type", ["MODE1/2048", "MODE2/2048"])
def test_a_lone_2048_byte_track_becomes_the_iso_without_bchunk(tmp_path, bchunk, track_type):
    bchunk["cue"] = "  TRACK 01 %s\n" % track_type

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is True

    assert len(bchunk["calls"]) == 1
    assert (tmp_path / "Game.iso").read_bytes() == b"binary"


@pytest.mark.parametrize("cue", ["  TRACK 01 MODE1/2048\n  TRACK 02 AUDIO\n", "  TRACK 01 CDG\n", ""])
def test_tracks_bchunk_cannot_split_report_failure(tmp_path, bchunk, cue):
    bchunk["cue"] = cue

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is False

    assert len(bchunk["calls"]) == 1
    assert sorted(path.name for path in tmp_path.iterdir()) == []


def test_a_failed_chdman_extraction_skips_bchunk(tmp_path, bchunk):
    bchunk["extracted"] = False

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is False

    assert len(bchunk["calls"]) == 1


def test_a_failed_bchunk_run_writes_no_iso(tmp_path, bchunk):
    bchunk["returncode"] = 1

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is False

    assert sorted(path.name for path in tmp_path.iterdir()) == []


@pytest.mark.parametrize("cue", ["  TRACK 01 MODE1/2048\n", "  TRACK 01 MODE2/2352\n"])
def test_a_failed_move_reports_failure(monkeypatch, tmp_path, bchunk, cue):
    bchunk["cue"] = cue
    monkeypatch.setattr(chd.fileops, "move_file_or_directory", lambda **kwargs: False)

    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso")) is False


def test_no_temporary_directory_reports_failure(monkeypatch, installed):
    monkeypatch.setattr(chd.fileops, "create_temporary_directory", lambda **kwargs: (False, "no space"))

    assert chd.extract_disc_chd_to_iso("/in/Game.chd", "/out/Game.iso") is False


def test_pretending_to_extract_an_iso_writes_nothing(tmp_path, installed, recording_command):
    assert chd.extract_disc_chd_to_iso(str(tmp_path / "Game.chd"), str(tmp_path / "Game.iso"), pretend_run = True) is True

    assert recording_command.only()[:2] == ["/tools/chdman", "extractcd"]
    assert sorted(path.name for path in tmp_path.iterdir()) == []


def test_iso_extraction_without_bchunk_reports_failure(missing):
    assert chd.extract_disc_chd_to_iso("/in/Game.chd", "/out/Game.iso") is False
