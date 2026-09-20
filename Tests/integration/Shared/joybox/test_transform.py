# Imports
import os
import pytest

# Local imports
from joybox import config, transform


###########################################################
# Game file transformation
#
# Turns a purchased or dumped file into what an emulator can load. Each
# platform needs a different chain, and a platform routed to the wrong one
# produces a file nothing can read.
###########################################################

class FakeGameInfo:

    def __init__(self, category = None, subcategory = None,
                 transform_file = "game.iso", key_file = "game.dkey"):
        self.category = category
        self.subcategory = subcategory
        self.transform_file = transform_file
        self.key_file = key_file

    def get_category(self):
        return self.category

    def get_subcategory(self):
        return self.subcategory

    def get_transform_file(self):
        return self.transform_file

    def get_key_file(self):
        return self.key_file


@pytest.fixture
def chains(monkeypatch, tmp_path):
    # Every transform writes its output into the temporary directory and
    # reports the path back, so the fakes do the same.
    calls = []

    def make(name, produces = "output.bin"):
        def run(**kwargs):
            calls.append((name, kwargs))
            target_dir = kwargs.get("output_dir") or str(tmp_path)
            os.makedirs(target_dir, exist_ok = True)
            produced = os.path.join(target_dir, produces)
            with open(produced, "w") as handle:
                handle.write(name)
            return (True, produced)
        return run

    for name in ["transform_computer_programs", "transform_disc_image",
                 "transform_xbox_disc_image", "transform_ps3_disc_image",
                 "transform_ps3_network_package", "transform_psv_network_package"]:
        monkeypatch.setattr(transform, name, make(name))
    return calls


@pytest.fixture
def workspace(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    (source / "game.iso").write_text("disc image")
    (source / "game.dkey").write_text("0123456789ABCDEF")
    return source, output


def names(calls):
    return [name for name, _ in calls]


###########################################################
# Platform routing
###########################################################

def test_a_computer_game_uses_the_program_transform(chains, workspace):
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER), str(source), str(output))

    assert success is True
    assert names(chains) == ["transform_computer_programs"]


@pytest.mark.parametrize("subcategory", [
    config.Subcategory.MICROSOFT_XBOX,
    config.Subcategory.MICROSOFT_XBOX_360,
])
def test_an_xbox_game_is_extracted_from_its_disc_image(chains, workspace, subcategory):
    # The image is unpacked first, then the xiso inside it.
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(subcategory = subcategory), str(source), str(output))

    assert names(chains) == ["transform_disc_image", "transform_xbox_disc_image"]


def test_a_ps3_disc_is_decrypted_after_unpacking(chains, workspace):
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.SONY_PLAYSTATION_3),
        str(source), str(output))

    assert names(chains) == ["transform_disc_image", "transform_ps3_disc_image"]


def test_a_ps3_disc_transform_gets_its_key_file(chains, workspace):
    # Without the dkey the image cannot be decrypted at all.
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.SONY_PLAYSTATION_3),
        str(source), str(output))
    kwargs = [entry for name, entry in chains if name == "transform_ps3_disc_image"][0]

    assert kwargs["source_file_dkey"].endswith("game.dkey")


def test_a_ps3_network_package_needs_no_disc_step(chains, workspace):
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.SONY_PLAYSTATION_NETWORK_PS3),
        str(source), str(output))

    assert names(chains) == ["transform_ps3_network_package"]


def test_a_vita_network_package_uses_its_own_transform(chains, workspace):
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.SONY_PLAYSTATION_NETWORK_PSV),
        str(source), str(output))

    assert names(chains) == ["transform_psv_network_package"]


def test_the_ps3_and_vita_packages_use_different_transforms(chains, workspace):
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.SONY_PLAYSTATION_NETWORK_PS3),
        str(source), str(output))
    transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.SONY_PLAYSTATION_NETWORK_PSV),
        str(source), str(output))

    assert names(chains) == ["transform_ps3_network_package", "transform_psv_network_package"]


def test_an_unhandled_platform_transforms_nothing(chains, workspace):
    # Most platforms load their files directly and need no transform.
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.NINTENDO_NES),
        str(source), str(output))

    assert success is False
    assert chains == []
    assert "No transformation" in result


def test_the_source_file_comes_from_the_source_directory(chains, workspace):
    source, output = workspace
    transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER), str(source), str(output))
    kwargs = chains[0][1]

    assert kwargs["source_file"] == os.path.join(str(source), "game.iso")


###########################################################
# Results
###########################################################

def test_a_successful_transform_lands_in_the_output_directory(chains, workspace):
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER), str(source), str(output))

    assert success is True
    assert result.startswith(str(output))
    assert os.path.exists(result)


def test_the_temporary_directory_is_cleaned_up(chains, workspace):
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER), str(source), str(output))
    temporary = [entry["output_dir"] for _, entry in chains][0]

    assert not os.path.exists(temporary)


def test_a_missing_output_directory_is_refused(chains, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    success, result = transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER),
        str(source), str(tmp_path / "absent"))

    assert success is False
    assert "Output directory" in result
    assert chains == []


def test_a_failing_transform_reports_its_reason(monkeypatch, workspace):
    monkeypatch.setattr(
        transform, "transform_computer_programs",
        lambda **kwargs: (False, "installer refused to run"))
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER), str(source), str(output))

    assert success is False
    assert result == "installer refused to run"


def test_a_failing_first_step_stops_the_chain(monkeypatch, chains, workspace):
    # The xbox chain unpacks then extracts; extracting a failed unpack would
    # operate on nothing.
    monkeypatch.setattr(
        transform, "transform_disc_image",
        lambda **kwargs: (False, "not a disc image"))
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(subcategory = config.Subcategory.MICROSOFT_XBOX),
        str(source), str(output))

    assert success is False
    assert "transform_xbox_disc_image" not in names(chains)


def test_a_transform_producing_nothing_is_a_failure(monkeypatch, workspace):
    # Reporting success is what puts an empty file into the collection.
    monkeypatch.setattr(
        transform, "transform_computer_programs",
        lambda **kwargs: (True, "/nowhere/missing.bin"))
    source, output = workspace
    success, result = transform.transform_game_file(
        FakeGameInfo(category = config.Category.COMPUTER), str(source), str(output))

    assert success is False
    assert "No transformation" in result
