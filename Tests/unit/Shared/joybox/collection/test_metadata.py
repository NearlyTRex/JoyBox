# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, metadata as metadata_module, metadataentry
from joybox.collection import metadata


###########################################################
# Game metadata entries
#
# The metadata file is what the front end reads, so an entry that is not
# written is a game nobody can see, and one that is rewritten from stale data
# loses whatever was filled in by hand.
###########################################################

ROMS = config.Supercategory.ROMS
CATEGORY = config.Category.COMPUTER
SUBCATEGORY = config.subcategory_map[config.Category.COMPUTER][0]
GAME = "Half-Life 2"


@pytest.fixture
def metadata_root(monkeypatch, tmp_path):
    # The metadata and json trees, rooted somewhere disposable.
    root = tmp_path / "metadata"
    json_root = tmp_path / "json"
    root.mkdir()
    json_root.mkdir()

    monkeypatch.setattr(
        metadata.environment, "get_game_metadata_file",
        lambda game_category, game_subcategory: str(
            root / ("%s - %s.txt" % (game_category, game_subcategory))))
    monkeypatch.setattr(
        metadata.environment, "get_game_json_metadata_file",
        lambda game_supercategory, game_category, game_subcategory, game_name: str(
            json_root / str(game_category) / str(game_subcategory) / (game_name + ".json")))
    monkeypatch.setattr(
        metadata.environment, "get_game_json_metadata_root_dir", lambda: str(json_root))
    monkeypatch.setattr(
        metadata.environment, "get_game_published_metadata_root_dir", lambda: str(tmp_path / "published"))
    return {"root": root, "json_root": json_root}


def metadata_file(metadata_root):
    return metadata_root["root"] / ("%s - %s.txt" % (CATEGORY, SUBCATEGORY))


def load(metadata_root):
    obj = metadata_module.Metadata()
    obj.import_from_metadata_file(metadata_file = str(metadata_file(metadata_root)))
    return obj


def platform_of():
    from joybox import gameinfo
    return gameinfo.derive_game_platform_from_categories(CATEGORY, SUBCATEGORY)


def create(metadata_root, **kwargs):
    defaults = dict(
        game_supercategory = ROMS,
        game_category = CATEGORY,
        game_subcategory = SUBCATEGORY,
        game_name = GAME)
    defaults.update(kwargs)
    return metadata.create_game_metadata_entry(**defaults)


###########################################################
# Which categories keep metadata
###########################################################

def test_games_keep_metadata_entries():
    assert metadata.are_game_metadata_file_possible(ROMS) is True


def test_anything_that_is_not_a_game_keeps_none():
    # Saves, dlc and updates hang off a game rather than being listed.
    for supercategory in config.Supercategory.members():
        if supercategory == ROMS:
            continue
        assert metadata.are_game_metadata_file_possible(supercategory) is False


###########################################################
# Creating an entry
###########################################################

def test_an_entry_is_written(metadata_root):
    assert create(metadata_root) is True
    assert metadata_file(metadata_root).is_file()


def test_a_created_entry_is_found_by_name(metadata_root):
    create(metadata_root)

    assert load(metadata_root).has_game(platform_of(), GAME) is True


def test_a_created_entry_knows_its_categories(metadata_root):
    create(metadata_root)

    entry = load(metadata_root).get_game(platform_of(), GAME)

    assert entry.get_category() == CATEGORY
    assert entry.get_subcategory() == SUBCATEGORY


def test_a_created_entry_points_at_its_json_file(metadata_root):
    # The path is stored relative to the json root so the collection can move.
    create(metadata_root)

    entry = load(metadata_root).get_game(platform_of(), GAME)

    assert entry.get_file().endswith(GAME + ".json")
    assert not entry.get_file().startswith(str(metadata_root["json_root"]))


@pytest.mark.parametrize("getter,expected", [
    ("get_players", "1"),
    ("get_coop", "No"),
    ("get_playable", "Yes"),
])
def test_a_created_entry_gets_sensible_defaults(metadata_root, getter, expected):
    # The front end filters on these, and an entry missing them is hidden.
    create(metadata_root)

    entry = load(metadata_root).get_game(platform_of(), GAME)

    assert getattr(entry, getter)() == expected


def test_a_store_url_is_recorded(metadata_root):
    create(metadata_root, game_url = "https://store.example/app/220")

    entry = load(metadata_root).get_game(platform_of(), GAME)

    assert entry.get_url() == "https://store.example/app/220"


@pytest.mark.parametrize("url", ["", None, "not-a-url", "ftp://example.test"])
def test_something_that_is_not_a_web_url_is_not_recorded(metadata_root, url):
    create(metadata_root, game_url = url)

    entry = load(metadata_root).get_game(platform_of(), GAME)

    assert not entry.get_url()


def test_initial_data_is_kept(metadata_root):
    initial = metadataentry.MetadataEntry()
    initial.set_developer("Valve")

    create(metadata_root, initial_data = initial)

    assert load(metadata_root).get_game(platform_of(), GAME).get_developer() == "Valve"


def test_initial_data_does_not_override_the_entrys_own_identity(metadata_root):
    initial = metadataentry.MetadataEntry()
    initial.set_game("Something Else")

    create(metadata_root, initial_data = initial)

    assert load(metadata_root).has_game(platform_of(), GAME) is True


def test_an_existing_entry_is_left_alone(metadata_root):
    # The entry holds scraped and hand-edited data; recreating it would
    # discard all of it.
    initial = metadataentry.MetadataEntry()
    initial.set_developer("Valve")
    create(metadata_root, initial_data = initial)

    replacement = metadataentry.MetadataEntry()
    replacement.set_developer("Someone Else")
    create(metadata_root, initial_data = replacement)

    assert load(metadata_root).get_game(platform_of(), GAME).get_developer() == "Valve"


def test_a_second_game_joins_the_same_file(metadata_root):
    create(metadata_root)
    create(metadata_root, game_name = "Portal")

    loaded = load(metadata_root)

    assert loaded.has_game(platform_of(), GAME) is True
    assert loaded.has_game(platform_of(), "Portal") is True


def test_a_category_without_metadata_writes_nothing(metadata_root):
    saves = [
        member for member in config.Supercategory.members() if member != ROMS][0]

    assert create(metadata_root, game_supercategory = saves) is True
    assert not metadata_file(metadata_root).exists()


###########################################################
# Updating an entry
###########################################################

@pytest.fixture
def scraping(monkeypatch):
    # Whatever a store or the scrapers would have returned.
    state = {"latest": None, "store": None, "collected": []}

    monkeypatch.setattr(
        metadata.stores, "get_store_by_platform", lambda **kwargs: state["store"])

    def collect_metadata_from_all(**kwargs):
        state["collected"].append(kwargs)
        return state["latest"]

    monkeypatch.setattr(
        metadata.metadatacollector, "collect_metadata_from_all", collect_metadata_from_all)
    monkeypatch.setattr(
        metadata, "read_game_json_data", lambda **kwargs: None)
    return state


def update(metadata_root, **kwargs):
    defaults = dict(
        game_supercategory = ROMS,
        game_category = CATEGORY,
        game_subcategory = SUBCATEGORY,
        game_name = GAME)
    defaults.update(kwargs)
    return metadata.update_game_metadata_entry(**defaults)


def scraped(**values):
    entry = metadataentry.MetadataEntry()
    for key, value in values.items():
        getattr(entry, "set_" + key)(value)
    return entry


def test_a_missing_entry_is_not_updated(metadata_root, scraping):
    assert update(metadata_root) is True
    assert scraping["collected"] == []


def test_an_incomplete_entry_is_filled_in(metadata_root, scraping):
    create(metadata_root)
    scraping["latest"] = scraped(developer = "Valve")

    assert update(metadata_root) is True
    assert load(metadata_root).get_game(platform_of(), GAME).get_developer() == "Valve"


def test_a_complete_entry_is_left_alone(metadata_root, scraping):
    # Scraping every entry on every run would hammer the sources for nothing.
    complete = metadataentry.MetadataEntry()
    for key in config.metadata_keys_downloadable:
        setter = getattr(complete, "set_" + key, None)
        if setter:
            setter("already here")
    create(metadata_root, initial_data = complete)

    update(metadata_root)

    assert scraping["collected"] == []


def test_a_complete_entry_can_be_refreshed_on_request(metadata_root, scraping):
    complete = metadataentry.MetadataEntry()
    for key in config.metadata_keys_downloadable:
        setter = getattr(complete, "set_" + key, None)
        if setter:
            setter("already here")
    create(metadata_root, initial_data = complete)

    update(metadata_root, force = True)

    assert len(scraping["collected"]) == 1


def test_an_update_scrapes_for_the_game_it_was_asked_about(metadata_root, scraping):
    create(metadata_root)

    update(metadata_root)

    assert scraping["collected"][0]["game_name"] == GAME


def test_nothing_found_leaves_the_entry_as_it_was(metadata_root, scraping):
    create(metadata_root)
    scraping["latest"] = None

    assert update(metadata_root) is True
    assert load(metadata_root).has_game(platform_of(), GAME) is True


def test_a_category_without_metadata_updates_nothing(metadata_root, scraping):
    saves = [
        member for member in config.Supercategory.members() if member != ROMS][0]

    assert update(metadata_root, game_supercategory = saves) is True
    assert scraping["collected"] == []


###########################################################
# Publishing
#
# The published html is what gets read on a phone away from the machine, so
# every entry in the metadata has to reach it.
###########################################################

@pytest.fixture
def published(tmp_path):
    return tmp_path / "published"


def publish(metadata_root):
    return metadata.publish_game_metadata_entries(ROMS, CATEGORY)


def published_file(published):
    return published / (str(CATEGORY) + ".html")


def test_publishing_writes_a_page_for_the_category(metadata_root, published):
    create(metadata_root)

    assert publish(metadata_root) is True
    assert published_file(published).is_file()


def test_a_published_page_names_every_game(metadata_root, published):
    create(metadata_root)
    create(metadata_root, game_name = "Portal")

    publish(metadata_root)
    contents = published_file(published).read_text()

    assert GAME in contents
    assert "Portal" in contents


def test_a_published_page_is_a_whole_document(metadata_root, published):
    create(metadata_root)

    publish(metadata_root)
    contents = published_file(published).read_text()

    assert contents.startswith(config.publish_html_header % CATEGORY)
    assert contents.endswith(config.publish_html_footer)


def test_a_category_with_no_metadata_still_publishes_a_page(metadata_root, published):
    # An empty page is how the front end shows a category with nothing in it.
    assert publish(metadata_root) is True
    assert published_file(published).is_file()


def test_published_rows_alternate(metadata_root, published):
    # The odd and even row templates are what make the table readable.
    create(metadata_root)
    create(metadata_root, game_name = "Portal")

    publish(metadata_root)
    contents = published_file(published).read_text()

    odd_marker = config.publish_html_entry_odd.split("%s")[0]
    even_marker = config.publish_html_entry_even.split("%s")[0]
    assert odd_marker in contents
    assert even_marker in contents
