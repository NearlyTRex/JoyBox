# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import mds
from mds_helpers import build_mds


@pytest.fixture
def image(tmp_path):
    def make(tracks, mdf_bytes = None, mds_name = "Game.mds", mdf_name = "Game.mdf", **kwargs):
        mds_file = tmp_path / mds_name
        mds_file.write_bytes(build_mds(tracks, **kwargs))
        if mdf_bytes is None:
            mdf_bytes = b"".join(
                bytes([index + 1]) * (track.get("length", 0) * track.get("sector_size", 2048))
                for index, track in enumerate(tracks))
        if mdf_name:
            (tmp_path / mdf_name).write_bytes(mdf_bytes)
        return str(mds_file)
    return make


@pytest.fixture
def logged(monkeypatch):
    messages = {"error": []}
    monkeypatch.setattr(mds.logger, "log_error", lambda message, **kwargs: messages["error"].append(message))
    return messages


@pytest.fixture
def work_dir(tmp_path):
    target = tmp_path / "work"
    target.mkdir()
    return target


def write_cue(image_file, work_dir):
    descriptor = mds.read_mds_descriptor(image_file)
    cue_file = work_dir / "Game.cue"
    assert mds.write_mds_cue_sheet(descriptor, str(cue_file)) is True
    return cue_file.read_text()


###########################################################
# Cue time
###########################################################

@pytest.mark.parametrize("frames, expected", [
    (0, "00:00:00"),
    (74, "00:00:74"),
    (75, "00:01:00"),
    (150, "00:02:00"),
    (60 * 75 + 1, "01:00:01"),
])
def test_frames_format_as_cue_time(frames, expected):
    assert mds.format_cue_time(frames) == expected


###########################################################
# Reading descriptors
###########################################################

def test_a_single_data_track_is_read(image, tmp_path):
    descriptor = mds.read_mds_descriptor(image([{"length": 10}]))

    [track] = descriptor["tracks"]
    assert descriptor["is_dvd"] is False
    assert track["number"] == 1
    assert track["cue_type"] == "MODE1/2048"
    assert track["length"] == 10
    assert track["pregap"] == 150
    assert track["data_file"] == str(tmp_path / "Game.mdf")


def test_lead_in_blocks_are_not_tracks(image):
    descriptor = mds.read_mds_descriptor(image([{"length": 4}, {"mode": 0xA9, "sector_size": 2352, "length": 4}]))

    assert [track["number"] for track in descriptor["tracks"]] == [1, 2]


@pytest.mark.parametrize("mode, sector_size, expected", [
    (0xA9, 2352, "AUDIO"),
    (0xAA, 2048, "MODE1/2048"),
    (0xAA, 2352, "MODE1/2352"),
    (0xAB, 2336, "MODE2/2336"),
    (0xAB, 2352, "MODE2/2352"),
    (0xAC, 2048, "MODE2/2048"),
    (0xAD, 2324, "MODE2/2324"),
    # Alcohol ignores the high bits of the mode
    (0xEC, 2352, "MODE2/2352"),
    (0x02, 2048, "MODE1/2048"),
])
def test_track_modes_map_to_cue_types(image, mode, sector_size, expected):
    descriptor = mds.read_mds_descriptor(image([{"mode": mode, "sector_size": sector_size, "length": 2}]))

    assert descriptor["tracks"][0]["cue_type"] == expected


def test_interleaved_subchannel_is_split_from_the_main_data(image):
    descriptor = mds.read_mds_descriptor(image([{"sector_size": 2448, "subchannel": 0x08, "length": 2}]))

    track = descriptor["tracks"][0]
    assert (track["main_size"], track["subchannel_size"]) == (2352, 96)
    assert track["cue_type"] == "MODE1/2352"


def test_a_named_data_file_is_found_without_matching_case(image, tmp_path):
    image_file = image([{"length": 2}], filename = "C:\\Rips\\GAME.MDF", mdf_name = "game.mdf")

    assert mds.read_mds_descriptor(image_file)["tracks"][0]["data_file"] == str(tmp_path / "game.mdf")


def test_a_wide_data_file_name_is_read(image, tmp_path):
    image_file = image([{"length": 2}], filename = "Spiel \u00fc.mdf", widechar = True, mdf_name = "Spiel \u00fc.mdf")

    assert mds.read_mds_descriptor(image_file)["tracks"][0]["data_file"] == str(tmp_path / "Spiel \u00fc.mdf")


def test_a_dvd_track_runs_to_the_end_of_its_data_file(image):
    image_file = image([{"sector_size": 2048, "mode": 0xAC}], medium = 0x10, mdf_bytes = b"\0" * 2048 * 7)
    descriptor = mds.read_mds_descriptor(image_file)

    assert descriptor["is_dvd"] is True
    assert descriptor["tracks"][0]["length"] == 7
    assert descriptor["tracks"][0]["cue_type"] == "MODE1/2048"
    assert descriptor["tracks"][0]["pregap"] == 0


def test_the_data_files_are_listed_once(image, tmp_path):
    descriptor = mds.read_mds_descriptor(image([{"length": 2}, {"length": 2, "start_offset": 4096}]))

    assert mds.get_mds_data_files(descriptor) == [str(tmp_path / "Game.mdf")]


@pytest.mark.parametrize("kwargs, tracks, message", [
    ({"signature": b"NOT A DESCRIPTOR"}, [{"length": 1}], "not a media descriptor"),
    ({"version": (2, 0)}, [{"length": 1}], "version 2.0"),
    ({"medium": 0x20}, [{"length": 1}], "medium type 0x20"),
    ({"sessions": 2}, [{"length": 1}], "2 sessions"),
    ({}, [{"length": 1, "files": 2}], "split over 2 data files"),
    ({}, [{"length": 1, "subchannel": 0x04}], "unknown subchannel type 0x04"),
    ({}, [{"length": 1, "mode": 0xAE}], "unknown mode 0xAE"),
    ({}, [{"length": 1, "sector_size": 2336}], "MODE1 with 2336-byte sectors"),
    ({}, [{"length": 0}], "track 1 is empty"),
    ({}, [{"length": 1, "no_extra": True}], "track 1 has no length"),
    ({"medium": 0x10}, [{"mode": 0xAC}, {"mode": 0xAC}], "2 tracks on a dvd"),
    ({"lead_in": True}, [], "no tracks"),
])
def test_descriptors_that_cannot_convert_are_reported(image, logged, kwargs, tracks, message):
    assert mds.read_mds_descriptor(image(tracks, mdf_bytes = b"\0" * 2048, **kwargs)) is None
    assert message in logged["error"][0]


@pytest.mark.parametrize("widechar, terminator", [(False, b"\0"), (True, b"\0\0")])
def test_an_unterminated_data_file_name_is_reported(tmp_path, logged, widechar, terminator):
    target = tmp_path / "Game.mds"
    target.write_bytes(build_mds([{"length": 1}], widechar = widechar)[:-len(terminator)])

    assert mds.read_mds_descriptor(str(target)) is None
    assert "runs past the end of the descriptor" in logged["error"][0]


def test_a_missing_data_file_is_reported(image, logged):
    assert mds.read_mds_descriptor(image([{"length": 1}], mdf_name = None)) is None
    assert "Game.mdf was not found" in logged["error"][0]


def test_a_truncated_descriptor_is_reported(tmp_path, logged):
    target = tmp_path / "Game.mds"
    target.write_bytes(build_mds([{"length": 1}])[:120])

    assert mds.read_mds_descriptor(str(target)) is None
    assert logged["error"][0].startswith("Unable to convert")


def test_an_unreadable_descriptor_is_reported(tmp_path, logged):
    assert mds.read_mds_descriptor(str(tmp_path / "absent.mds")) is None
    assert logged["error"] == ["Unable to read %s" % (tmp_path / "absent.mds")]


###########################################################
# Writing cue sheets
###########################################################

def test_a_plain_image_is_read_in_place(image, work_dir):
    cue = write_cue(image([{"length": 10}]), work_dir)

    assert cue == (
        "FILE \"../Game.mdf\" BINARY\n"
        "  TRACK 01 MODE1/2048\n"
        "    INDEX 01 00:00:00\n")
    assert sorted(os.listdir(work_dir)) == ["Game.cue"]


def test_later_tracks_index_from_the_frames_before_them(image, work_dir):
    cue = write_cue(image([
        {"sector_size": 2352, "length": 100},
        {"mode": 0xA9, "sector_size": 2352, "length": 50, "pregap": 150, "start_offset": 100 * 2352},
        {"mode": 0xA9, "sector_size": 2352, "length": 20, "pregap": 0, "start_offset": 150 * 2352},
    ]), work_dir)

    assert cue == (
        "FILE \"../Game.mdf\" BINARY\n"
        "  TRACK 01 MODE1/2352\n"
        "    INDEX 01 00:00:00\n"
        "  TRACK 02 AUDIO\n"
        "    PREGAP 00:02:00\n"
        "    INDEX 01 00:01:25\n"
        "  TRACK 03 AUDIO\n"
        "    INDEX 01 00:02:00\n")


def test_a_first_pregap_longer_than_standard_keeps_the_excess(image, work_dir):
    cue = write_cue(image([{"length": 4, "pregap": 225}]), work_dir)

    assert "    PREGAP 00:01:00\n" in cue


def test_subchannel_data_is_stripped_into_track_files(image, work_dir):
    sectors = [bytes([n]) * 2352 + b"\xee" * 96 for n in range(3)]
    cue = write_cue(image([{"sector_size": 2448, "subchannel": 0x08, "length": 3}], mdf_bytes = b"".join(sectors)), work_dir)

    assert cue == (
        "FILE \"Track 01.bin\" BINARY\n"
        "  TRACK 01 MODE1/2352\n"
        "    INDEX 01 00:00:00\n")
    assert (work_dir / "Track 01.bin").read_bytes() == b"".join(bytes([n]) * 2352 for n in range(3))


def test_tracks_that_do_not_start_the_data_file_are_copied_out(image, work_dir):
    cue = write_cue(image([{"length": 2, "start_offset": 2048}], mdf_bytes = b"\x01" * 2048 + b"\x02" * 4096), work_dir)

    assert "FILE \"Track 01.bin\" BINARY\n" in cue
    assert (work_dir / "Track 01.bin").read_bytes() == b"\x02" * 4096


def test_a_data_file_with_trailing_bytes_is_copied_out(image, work_dir):
    cue = write_cue(image([{"length": 2}], mdf_bytes = b"\x01" * 4096 + b"junk"), work_dir)

    assert "FILE \"Track 01.bin\" BINARY\n" in cue
    assert (work_dir / "Track 01.bin").read_bytes() == b"\x01" * 4096


def test_each_copied_track_gets_its_own_file(image, work_dir):
    mdf = b"\x01" * 2448 * 2 + b"\x02" * 2448 * 3
    cue = write_cue(image([
        {"sector_size": 2448, "subchannel": 0x08, "length": 2},
        {"mode": 0xA9, "sector_size": 2448, "subchannel": 0x08, "length": 3, "pregap": 150, "start_offset": 2448 * 2},
    ], mdf_bytes = mdf), work_dir)

    assert cue == (
        "FILE \"Track 01.bin\" BINARY\n"
        "  TRACK 01 MODE1/2352\n"
        "    INDEX 01 00:00:00\n"
        "FILE \"Track 02.bin\" BINARY\n"
        "  TRACK 02 AUDIO\n"
        "    PREGAP 00:02:00\n"
        "    INDEX 01 00:00:00\n")
    assert (work_dir / "Track 02.bin").read_bytes() == b"\x02" * 2352 * 3


def test_a_data_file_path_a_cue_cannot_quote_is_copied_out(image, work_dir, monkeypatch):
    monkeypatch.setattr(mds.paths, "get_relative_path", lambda path, start_dir: "../Game \"1\".mdf")

    assert "FILE \"Track 01.bin\" BINARY\n" in write_cue(image([{"length": 2}]), work_dir)


def test_a_data_file_on_another_drive_is_copied_out(image, work_dir, monkeypatch):
    monkeypatch.setattr(mds.paths, "get_relative_path", lambda path, start_dir: None)

    assert "FILE \"Track 01.bin\" BINARY\n" in write_cue(image([{"length": 2}]), work_dir)


def test_tracks_in_several_data_files_are_not_read_in_place():
    descriptor = {"tracks": [{"data_file": "/in/a.mdf"}, {"data_file": "/in/b.mdf"}]}

    assert mds.can_read_mdf_in_place(descriptor) is False


def test_a_short_data_file_fails_the_copy(image, work_dir, logged):
    descriptor = mds.read_mds_descriptor(image([{"sector_size": 2448, "subchannel": 0x08, "length": 3}], mdf_bytes = b"\0" * 2448))

    assert mds.write_mds_cue_sheet(descriptor, str(work_dir / "Game.cue")) is False
    assert logged["error"][0].startswith("Unable to copy track 1")
    assert not (work_dir / "Game.cue").exists()


def test_a_pretend_run_writes_nothing(image, work_dir):
    descriptor = mds.read_mds_descriptor(image([{"sector_size": 2448, "subchannel": 0x08, "length": 2}]))

    assert mds.write_mds_cue_sheet(descriptor, str(work_dir / "Game.cue"), pretend_run = True) is True
    assert os.listdir(work_dir) == []


###########################################################
# Converting for chdman
###########################################################

def test_converting_writes_a_cue_named_after_the_image(image, work_dir, tmp_path):
    cue_file, source_files = mds.convert_mds_to_cue(image([{"length": 2}]), str(work_dir))

    assert cue_file == str(work_dir / "Game.cue")
    assert (work_dir / "Game.cue").read_text().startswith("FILE \"../Game.mdf\" BINARY\n")
    assert source_files == [str(tmp_path / "Game.mds"), str(tmp_path / "Game.mdf")]


def test_converting_an_unreadable_image_gives_nothing(image, work_dir, logged):
    assert mds.convert_mds_to_cue(image([{"length": 1}], mdf_name = None), str(work_dir)) is None
    assert os.listdir(work_dir) == []


def test_converting_gives_nothing_when_the_cue_cannot_be_written(image, work_dir, logged):
    image_file = image([{"sector_size": 2448, "subchannel": 0x08, "length": 3}], mdf_bytes = b"\0" * 2448)

    assert mds.convert_mds_to_cue(image_file, str(work_dir)) is None
