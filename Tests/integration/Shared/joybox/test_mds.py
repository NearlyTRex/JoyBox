# Imports
import os
import re

# Third-party imports
import pytest

# Local imports
from joybox import chd
from mds_helpers import build_mds

pytestmark = [
    pytest.mark.requires_tool("MameChdman"),
    pytest.mark.slow,
]


###########################################################
# MDS to CHD
#
# Runs the real chdman on synthetic Alcohol images, then extracts the CHD back
# to a cue sheet so the tracks chdman stored can be compared with the image.
###########################################################

def write_image(tmp_path, tracks, sectors):
    (tmp_path / "Game.mds").write_bytes(build_mds(tracks))
    (tmp_path / "Game.mdf").write_bytes(b"".join(sectors))
    return str(tmp_path / "Game.mds")


def convert_and_extract(tmp_path, mds_file):
    chd_file = str(tmp_path / "Game.chd")
    assert chd.create_disc_chd(chd_file, mds_file) is True
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    assert chd.extract_disc_chd(chd_file, str(out_dir / "Game.bin"), str(out_dir / "Game.cue")) is True
    cue = (out_dir / "Game.cue").read_text()
    return re.findall(r"TRACK \d+ (\S+)", cue), (out_dir / "Game.bin").read_bytes()


def test_a_cooked_data_image_keeps_its_sectors(tmp_path):
    sectors = [os.urandom(2048) for _ in range(40)]
    mds_file = write_image(tmp_path, [{"length": 40}], sectors)

    track_types, data = convert_and_extract(tmp_path, mds_file)

    assert track_types == ["MODE1/2048"]
    assert data == b"".join(sectors)


def test_a_mixed_mode_image_with_subchannel_keeps_its_main_data(tmp_path):
    data_sectors = [os.urandom(2352) for _ in range(30)]
    audio_sectors = [os.urandom(2352) for _ in range(20)]
    tracks = [
        {"sector_size": 2448, "subchannel": 0x08, "mode": 0xAA, "length": 30},
        {"sector_size": 2448, "subchannel": 0x08, "mode": 0xA9, "length": 20, "pregap": 150, "start_offset": 30 * 2448},
    ]
    sectors = [sector + b"\xee" * 96 for sector in data_sectors + audio_sectors]
    mds_file = write_image(tmp_path, tracks, sectors)

    track_types, data = convert_and_extract(tmp_path, mds_file)

    assert track_types == ["MODE1/2352", "AUDIO"]
    assert data[:30 * 2352] == b"".join(data_sectors)
    assert data.endswith(b"".join(audio_sectors))
    assert b"\xee" * 96 not in data


def test_an_mds_image_is_deleted_with_its_data_file_when_asked(tmp_path):
    mds_file = write_image(tmp_path, [{"length": 10}], [os.urandom(2048) for _ in range(10)])

    assert chd.create_disc_chd(str(tmp_path / "Game.chd"), mds_file, delete_original = True) is True
    assert sorted(os.listdir(tmp_path)) == ["Game.chd"]
