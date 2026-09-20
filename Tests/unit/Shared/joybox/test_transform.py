# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, transform


###########################################################
# Individual transform chains
#
# Each chain turns one platform's delivered files into what an emulator can
# load. The steps run in a fixed order against real tools, so what is pinned
# here is which step ran, on which file, and what a failure does to the rest
# of the chain.
###########################################################

class FakeGameInfo:

    def __init__(self, name = "A Game", category = None, subcategory = None):
        self.name = name
        self.category = category
        self.subcategory = subcategory

    def get_name(self):
        return self.name

    def get_category(self):
        return self.category

    def get_subcategory(self):
        return self.subcategory


def write(path, contents = "data"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(contents)
    return path


###########################################################
# Disc images
###########################################################

@pytest.fixture
def extracted_chd(monkeypatch):
    # Records the extraction rather than running chdman over a real image.
    calls = []

    def extract_disc_chd(chd_file, binary_file, toc_file, **kwargs):
        calls.append({"chd": chd_file, "binary": binary_file, "toc": toc_file})
        return True

    monkeypatch.setattr(transform.chd, "extract_disc_chd", extract_disc_chd)
    return calls


def test_a_chd_is_extracted_to_an_iso(extracted_chd, tmp_path):
    source = write(tmp_path / "discs" / "Game.chd")
    output = str(tmp_path / "out")

    success, result = transform.transform_disc_image(source, output)

    assert success is True
    assert result == os.path.join(output, "Game" + config.DiscImageFileType.ISO.cval())


def test_an_extracted_disc_keeps_its_table_of_contents(extracted_chd, tmp_path):
    # The toc carries the track layout; a mixed mode disc without it loses its
    # audio tracks.
    source = write(tmp_path / "discs" / "Game.chd")
    output = str(tmp_path / "out")

    transform.transform_disc_image(source, output)

    assert extracted_chd[0]["toc"] == os.path.join(output, "Game.toc")


def test_the_chd_is_read_from_beside_the_source(extracted_chd, tmp_path):
    source = write(tmp_path / "discs" / "Game.chd")

    transform.transform_disc_image(source, str(tmp_path / "out"))

    assert extracted_chd[0]["chd"] == source


def test_a_failed_extraction_reports_its_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.chd, "extract_disc_chd", lambda **kwargs: False)
    source = write(tmp_path / "discs" / "Game.chd")

    success, result = transform.transform_disc_image(source, str(tmp_path / "out"))

    assert success is False
    assert result == "Unable to extract disc images"


def test_every_disc_in_a_playlist_is_extracted(extracted_chd, tmp_path):
    source = write(tmp_path / "discs" / "Game.m3u", "Game (Disc 1).chd\nGame (Disc 2).chd\n")

    transform.transform_disc_image(source, str(tmp_path / "out"))

    assert [os.path.basename(call["chd"]) for call in extracted_chd] == \
        ["Game (Disc 1).chd", "Game (Disc 2).chd"]


def test_a_playlist_is_rewritten_to_point_at_the_extracted_discs(extracted_chd, tmp_path):
    # The emulator loads the playlist, so entries still naming .chd files
    # point at images that are no longer there.
    source = write(tmp_path / "discs" / "Game.m3u", "Game (Disc 1).chd\nGame (Disc 2).chd\n")
    output = str(tmp_path / "out")

    success, result = transform.transform_disc_image(source, output)

    assert success is True
    assert result == os.path.join(output, "Game.m3u")
    with open(result) as handle:
        assert handle.read().splitlines() == ["Game (Disc 1).iso", "Game (Disc 2).iso"]


def test_a_file_that_is_neither_a_disc_nor_a_playlist_is_left_alone(extracted_chd, tmp_path):
    source = write(tmp_path / "discs" / "Game.rom")

    success, result = transform.transform_disc_image(source, str(tmp_path / "out"))

    assert success is False
    assert result == source


###########################################################
# Xbox disc images
###########################################################

@pytest.fixture
def rewritten_xbox(monkeypatch):
    calls = []

    def rewrite_xbox_iso(iso_file, **kwargs):
        calls.append({"iso": iso_file, "delete": kwargs.get("delete_original")})
        return True

    monkeypatch.setattr(transform.xbox, "rewrite_xbox_iso", rewrite_xbox_iso)
    return calls


def test_an_xbox_image_is_rewritten_in_place(rewritten_xbox, tmp_path):
    source = write(tmp_path / "discs" / "Game.iso")
    output = str(tmp_path / "out")

    success, result = transform.transform_xbox_disc_image(source, output)

    assert success is True
    assert result == os.path.join(output, "Game.iso")
    assert rewritten_xbox[0]["iso"] == source


def test_rewriting_replaces_the_original_image(rewritten_xbox, tmp_path):
    # The redump image and the rewritten one are the same size, and keeping
    # both doubles what the transform costs on disk.
    source = write(tmp_path / "discs" / "Game.iso")

    transform.transform_xbox_disc_image(source, str(tmp_path / "out"))

    assert rewritten_xbox[0]["delete"] is True


def test_every_xbox_disc_in_a_playlist_is_rewritten(rewritten_xbox, tmp_path):
    source = write(tmp_path / "discs" / "Game.m3u", "Game (Disc 1).iso\nGame (Disc 2).iso\n")

    transform.transform_xbox_disc_image(source, str(tmp_path / "out"))

    assert len(rewritten_xbox) == 2


def test_a_failed_xbox_rewrite_reports_its_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.xbox, "rewrite_xbox_iso", lambda **kwargs: False)
    source = write(tmp_path / "discs" / "Game.iso")

    success, result = transform.transform_xbox_disc_image(source, str(tmp_path / "out"))

    assert success is False
    assert result == "Unable to rewrite xbox disc images"


###########################################################
# PS3 disc images
###########################################################

@pytest.fixture
def ps3_tools(monkeypatch):
    calls = {"iso": [], "pkg": []}

    def extract_ps3_iso(iso_file, dkey_file, extract_dir, **kwargs):
        calls["iso"].append({"iso": iso_file, "dkey": dkey_file, "dir": extract_dir})
        return True

    def extract_psn_pkg(pkg_file, extract_dir, **kwargs):
        calls["pkg"].append({"pkg": pkg_file, "dir": extract_dir})
        return True

    monkeypatch.setattr(transform.playstation, "extract_ps3_iso", extract_ps3_iso)
    monkeypatch.setattr(transform.playstation, "extract_psn_pkg", extract_psn_pkg)
    return calls


def test_a_ps3_disc_is_decrypted_with_its_key(ps3_tools, tmp_path):
    source = write(tmp_path / "discs" / "Game.iso")
    key = write(tmp_path / "discs" / "Game.dkey", "0123456789ABCDEF")
    output = str(tmp_path / "out")

    success, result = transform.transform_ps3_disc_image(source, key, output)

    assert success is True
    assert ps3_tools["iso"][0]["dkey"] == key
    assert result == os.path.join(output, config.raw_files_index)


def test_a_ps3_transform_leaves_an_index_behind(ps3_tools, tmp_path):
    # The index marks the directory as already unpacked raw files.
    source = write(tmp_path / "discs" / "Game.iso")
    output = str(tmp_path / "out")

    transform.transform_ps3_disc_image(source, "/keys/Game.dkey", output)

    assert os.path.isfile(os.path.join(output, config.raw_files_index))


def test_a_failed_ps3_decryption_reports_its_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.playstation, "extract_ps3_iso", lambda **kwargs: False)
    source = write(tmp_path / "discs" / "Game.iso")

    success, result = transform.transform_ps3_disc_image(
        source, "/keys/Game.dkey", str(tmp_path / "out"))

    assert success is False
    assert result == "Unable to extract ps3 disc images"


@pytest.mark.parametrize("relative", [
    os.path.join("PS3_GAME", "PKGDIR", "extra.pkg"),
    os.path.join("PS3_EXTRA", "bonus.pkg"),
])
def test_packages_inside_the_disc_are_unpacked(ps3_tools, tmp_path, relative):
    source = write(tmp_path / "discs" / "Game.iso")
    output = tmp_path / "out"
    write(output / relative)

    transform.transform_ps3_disc_image(source, "/keys/Game.dkey", str(output))

    assert ps3_tools["pkg"][0]["pkg"] == str(output / relative)


def test_a_package_elsewhere_on_the_disc_is_left_packed(ps3_tools, tmp_path):
    # Only the two known locations hold installable packages; anything else is
    # game data that the emulator reads as it is.
    source = write(tmp_path / "discs" / "Game.iso")
    output = tmp_path / "out"
    write(output / "PS3_GAME" / "USRDIR" / "data.pkg")

    transform.transform_ps3_disc_image(source, "/keys/Game.dkey", str(output))

    assert ps3_tools["pkg"] == []


def test_a_disc_package_is_unpacked_beside_itself(ps3_tools, tmp_path):
    source = write(tmp_path / "discs" / "Game.iso")
    output = tmp_path / "out"
    write(output / "PS3_EXTRA" / "bonus.pkg")

    transform.transform_ps3_disc_image(source, "/keys/Game.dkey", str(output))

    assert ps3_tools["pkg"][0]["dir"] == str(output / "PS3_EXTRA" / "bonus")


def test_a_failed_disc_package_extract_reports_its_reason(ps3_tools, monkeypatch, tmp_path):
    monkeypatch.setattr(transform.playstation, "extract_psn_pkg", lambda **kwargs: False)
    source = write(tmp_path / "discs" / "Game.iso")
    output = tmp_path / "out"
    write(output / "PS3_EXTRA" / "bonus.pkg")

    success, result = transform.transform_ps3_disc_image(
        source, "/keys/Game.dkey", str(output))

    assert success is False
    assert result == "Unable to extract ps3 pkg files"


###########################################################
# Network packages
###########################################################

@pytest.fixture
def psn_tools(monkeypatch):
    calls = {"pkg": [], "copied": []}

    def extract_psn_pkg(pkg_file, extract_dir, **kwargs):
        calls["pkg"].append({"pkg": pkg_file, "dir": extract_dir})
        return True

    def copy_file_or_directory(src, dest, **kwargs):
        calls["copied"].append((src, dest))
        return True

    monkeypatch.setattr(transform.playstation, "extract_psn_pkg", extract_psn_pkg)
    monkeypatch.setattr(transform.fileops, "copy_file_or_directory", copy_file_or_directory)
    return calls


def test_a_ps3_package_is_unpacked(psn_tools, tmp_path):
    source = write(tmp_path / "downloads" / "Game.pkg")
    output = str(tmp_path / "out")

    success, result = transform.transform_ps3_network_package(source, output)

    assert success is True
    assert psn_tools["pkg"][0] == {"pkg": source, "dir": output}
    assert result == os.path.join(output, config.raw_files_index)


def test_a_licence_is_renamed_to_its_content_id(psn_tools, monkeypatch, tmp_path):
    # The console looks the licence up by content id, not by the name the
    # store happened to give the download.
    monkeypatch.setattr(
        transform.playstation, "get_psn_package_content_id",
        lambda pkg_file: "UP0001-TEST00000_00-0000000000000000")
    source = write(tmp_path / "downloads" / "Game.pkg")
    write(tmp_path / "downloads" / "Game.rap")
    output = str(tmp_path / "out")

    transform.transform_ps3_network_package(source, output)

    assert psn_tools["copied"] == [(
        str(tmp_path / "downloads" / "Game.rap"),
        os.path.join(output, "UP0001-TEST00000_00-0000000000000000.rap"))]


def test_a_licence_without_a_package_is_not_copied(psn_tools, monkeypatch, tmp_path):
    monkeypatch.setattr(
        transform.playstation, "get_psn_package_content_id", lambda pkg_file: None)
    source = write(tmp_path / "downloads" / "Game.pkg")
    write(tmp_path / "downloads" / "Orphan.rap")

    transform.transform_ps3_network_package(source, str(tmp_path / "out"))

    assert psn_tools["copied"] == []


def test_every_package_in_the_download_is_unpacked(psn_tools, tmp_path):
    source = write(tmp_path / "downloads" / "Game.pkg")
    write(tmp_path / "downloads" / "Game-Update.pkg")

    transform.transform_ps3_network_package(source, str(tmp_path / "out"))

    assert len(psn_tools["pkg"]) == 2


def test_a_failed_package_extract_reports_its_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.playstation, "extract_psn_pkg", lambda **kwargs: False)
    source = write(tmp_path / "downloads" / "Game.pkg")

    success, result = transform.transform_ps3_network_package(source, str(tmp_path / "out"))

    assert success is False
    assert result == "Unable to extract ps3 pkg files"


def test_a_vita_package_keeps_its_licence_as_work_bin(psn_tools, tmp_path):
    # The Vita reads exactly one file called work.bin, whatever the download
    # named it.
    source = write(tmp_path / "downloads" / "Game.pkg")
    write(tmp_path / "downloads" / "Game.work.bin")
    output = str(tmp_path / "out")

    success, result = transform.transform_psv_network_package(source, output)

    assert success is True
    assert psn_tools["copied"] == [(
        str(tmp_path / "downloads" / "Game.work.bin"),
        os.path.join(output, "work.bin"))]


def test_a_vita_package_is_unpacked(psn_tools, tmp_path):
    source = write(tmp_path / "downloads" / "Game.pkg")
    output = str(tmp_path / "out")

    transform.transform_psv_network_package(source, output)

    assert psn_tools["pkg"][0] == {"pkg": source, "dir": output}


@pytest.mark.parametrize("builder", [
    transform.transform_ps3_network_package,
    transform.transform_psv_network_package,
])
def test_a_network_transform_leaves_an_index_behind(psn_tools, tmp_path, builder):
    source = write(tmp_path / "downloads" / "Game.pkg")
    output = str(tmp_path / "out")

    builder(source, output)

    assert os.path.isfile(os.path.join(output, config.raw_files_index))


###########################################################
# Computer programs
###########################################################

@pytest.fixture
def computer_tools(monkeypatch, tmp_path):
    calls = {"extracted": [], "installed": [], "unpacked": [], "transferred": []}

    monkeypatch.setattr(
        transform.environment, "get_cache_gaming_install_dir",
        lambda category, subcategory, name: str(tmp_path / "cache" / name))
    monkeypatch.setattr(
        transform.archive, "extract_archive",
        lambda archive_file, extract_dir, **kwargs: calls["extracted"].append(archive_file) or True)
    monkeypatch.setattr(
        transform.computer, "setup_computer_game",
        lambda **kwargs: calls["installed"].append(kwargs["output_image"]) or True)
    monkeypatch.setattr(
        transform.fileops, "smart_transfer",
        lambda src, dest, **kwargs: calls["transferred"].append((src, dest)) or True)
    monkeypatch.setattr(
        transform.install, "unpack_install_image",
        lambda input_image, output_dir, **kwargs: calls["unpacked"].append(input_image) or True)
    return calls


def test_a_prepackaged_archive_is_extracted_rather_than_installed(computer_tools, tmp_path):
    # A game that was packaged by hand needs no installer run at all.
    source = write(tmp_path / "source" / "setup.exe")
    archive_file = write(tmp_path / "source" / "A Game.7z")

    success, _ = transform.transform_computer_programs(
        FakeGameInfo(), source, str(tmp_path / "out"))

    assert success is True
    assert computer_tools["extracted"] == [archive_file]
    assert computer_tools["installed"] == []


def test_a_split_prepackaged_archive_is_found(computer_tools, tmp_path):
    source = write(tmp_path / "source" / "setup.exe")
    first_part = write(tmp_path / "source" / "A Game.7z.001")

    transform.transform_computer_programs(FakeGameInfo(), source, str(tmp_path / "out"))

    assert computer_tools["extracted"] == [first_part]


def test_an_installer_is_run_when_nothing_is_prepackaged(computer_tools, tmp_path):
    source = write(tmp_path / "source" / "setup.exe")

    success, _ = transform.transform_computer_programs(
        FakeGameInfo(), source, str(tmp_path / "out"))

    assert success is True
    assert len(computer_tools["installed"]) == 1


def test_a_new_install_image_is_cached(computer_tools, tmp_path):
    # Installing is the slow step; the image is kept so the next transform of
    # the same game skips it.
    source = write(tmp_path / "source" / "setup.exe")

    transform.transform_computer_programs(FakeGameInfo(), source, str(tmp_path / "out"))

    assert computer_tools["transferred"] == [(
        os.path.join(str(tmp_path / "out"), "A Game.install"),
        os.path.join(str(tmp_path / "cache" / "A Game"), "A Game.install"))]


def test_a_cached_install_image_is_reused(computer_tools, tmp_path):
    source = write(tmp_path / "source" / "setup.exe")
    cached = write(tmp_path / "cache" / "A Game" / "A Game.install")

    transform.transform_computer_programs(FakeGameInfo(), source, str(tmp_path / "out"))

    assert computer_tools["installed"] == []
    assert computer_tools["unpacked"] == [cached]


def test_a_failed_install_reports_its_reason(computer_tools, monkeypatch, tmp_path):
    monkeypatch.setattr(transform.computer, "setup_computer_game", lambda **kwargs: False)
    source = write(tmp_path / "source" / "setup.exe")

    success, result = transform.transform_computer_programs(
        FakeGameInfo(), source, str(tmp_path / "out"))

    assert success is False
    assert result == "Unable to install computer game"


def test_a_failed_extract_reports_its_reason(computer_tools, monkeypatch, tmp_path):
    monkeypatch.setattr(transform.archive, "extract_archive", lambda **kwargs: False)
    source = write(tmp_path / "source" / "setup.exe")
    write(tmp_path / "source" / "A Game.7z")

    success, result = transform.transform_computer_programs(
        FakeGameInfo(), source, str(tmp_path / "out"))

    assert success is False
    assert result == "Unable to extract game"


def test_a_computer_transform_leaves_an_index_behind(computer_tools, tmp_path):
    source = write(tmp_path / "source" / "setup.exe")

    success, result = transform.transform_computer_programs(
        FakeGameInfo(), source, str(tmp_path / "out"))

    assert success is True
    assert os.path.isfile(result)
    assert result.endswith(config.raw_files_index)
