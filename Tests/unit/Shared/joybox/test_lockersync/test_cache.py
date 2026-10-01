# Local imports
from joybox import lockersync


###########################################################
# The hash map cache
###########################################################

def test_the_cache_directory_is_created_on_demand(cache_dir):
    assert lockersync.get_cache_dir() == str(cache_dir)
    assert cache_dir.is_dir()


def test_each_locker_caches_under_its_own_name(cache_dir):
    first = lockersync.get_cache_file("hetzner")
    second = lockersync.get_cache_file("backblaze")

    assert first != second
    assert first.endswith("hetzner_hashmap.json")


def test_clearing_the_cache_empties_it(cache_dir):
    lockersync.get_cache_dir()
    (cache_dir / "hetzner_hashmap.json").write_text("{}")

    lockersync.clear_cache()

    assert list(cache_dir.iterdir()) == []


def test_clearing_an_empty_cache_is_harmless(cache_dir):
    lockersync.clear_cache()

    assert cache_dir.is_dir()


def test_clearing_a_cache_that_could_not_be_made_is_harmless(cache_dir, monkeypatch):
    monkeypatch.setattr(lockersync.fileops, "make_directory", lambda **kwargs: False)

    lockersync.clear_cache()

    assert not cache_dir.exists()


def test_excludes_get_their_own_cache_file(cache_dir):
    assert lockersync.get_cache_file("hetzner", ["Cache/**"]) != lockersync.get_cache_file("hetzner")
    assert lockersync.get_cache_file("hetzner", ["Cache/**"]) != \
        lockersync.get_cache_file("hetzner", ["Logs/**"])


def test_the_order_of_excludes_does_not_matter(cache_dir):
    assert lockersync.get_cache_file("hetzner", ["A/**", "B/**"]) == \
        lockersync.get_cache_file("hetzner", ["B/**", "A/**"])


def test_an_excluded_cache_is_still_named_for_its_locker(cache_dir):
    assert lockersync.get_cache_file("hetzner", ["Cache/**"]).startswith(
        str(cache_dir / "hetzner_"))
