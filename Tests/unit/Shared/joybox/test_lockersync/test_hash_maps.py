# Imports
import json
import os
import time

# Third-party imports
import pytest

# Local imports
from joybox import config, lockersync
from lockersync_helpers import FakeLocalLocker, FakeRemoteLocker, entry


###########################################################
# Building a locker's hash map
#
# The map is what the sync compares. A failed listing must come back as a
# failure: read as an empty locker, every file on the other side would be
# copied again or recycled as an orphan.
###########################################################

def build(backend, name = "Locker", **kwargs):
    return lockersync.build_locker_hash_map(backend = backend, locker_name = name, **kwargs)


def write_cache(path, data, age_hours = 0):
    path.parent.mkdir(parents = True, exist_ok = True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    stamp = time.time() - age_hours * 3600
    os.utime(str(path), (stamp, stamp))


def test_a_local_locker_is_listed(cache_dir, tmp_path):
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker) == {"Game.zip": entry()}
    assert locker.sidecar_reads == []


def test_the_excludes_reach_the_listing(cache_dir, tmp_path):
    locker = FakeLocalLocker(str(tmp_path))
    build(locker, excludes = ["Cache/**"])

    assert locker.listed[0]["excludes"] == ["Cache/**"]


def test_run_flags_reach_the_listing(cache_dir, tmp_path):
    locker = FakeLocalLocker(str(tmp_path))
    build(locker, pretend_run = True, exit_on_failure = True)

    assert locker.listed[0]["pretend_run"] is True
    assert locker.listed[0]["exit_on_failure"] is True


def test_a_failed_listing_is_a_failure(cache_dir, tmp_path, messages):
    locker = FakeLocalLocker(str(tmp_path))
    locker.listing = None

    assert build(locker) is None
    assert messages["error"]


def test_an_empty_locker_is_empty_rather_than_failed(cache_dir, tmp_path):
    assert build(FakeLocalLocker(str(tmp_path))) == {}


def test_a_built_map_is_cached(cache_dir, tmp_path):
    build(FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()}))

    with open(lockersync.get_cache_file("Locker")) as handle:
        assert json.load(handle) == {"Game.zip": entry()}


def test_an_empty_map_is_not_cached(cache_dir, tmp_path):
    build(FakeLocalLocker(str(tmp_path)))

    assert not os.path.exists(lockersync.get_cache_file("Locker"))


def test_a_map_built_with_excludes_is_cached_apart(cache_dir, tmp_path):
    # A full map read back for an excluded run, or the other way round, would
    # be missing files or hold files that run never looks at.
    build(FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()}), excludes = ["Cache/**"])

    assert os.path.exists(lockersync.get_cache_file("Locker", ["Cache/**"]))
    assert not os.path.exists(lockersync.get_cache_file("Locker"))


def test_a_verbose_build_reports_its_size(cache_dir, tmp_path, messages):
    build(FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()}), verbose = True)

    assert "Hash map for Locker: 1 files" in messages["info"]


###########################################################
# The cache
###########################################################

def test_a_recent_cache_is_used_instead_of_listing(cache_dir, tmp_path, messages):
    write_cache(cache_dir / "Locker_hashmap.json", {"Cached.zip": entry()}, age_hours = 1)
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker, verbose = True) == {"Cached.zip": entry()}
    assert locker.listed == []
    assert any("Using cached hash map" in message for message in messages["info"])


def test_a_cache_can_be_skipped(cache_dir, tmp_path):
    write_cache(cache_dir / "Locker_hashmap.json", {"Cached.zip": entry()})
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker, use_cache = False) == {"Game.zip": entry()}


def test_an_old_cache_is_rebuilt(cache_dir, tmp_path):
    write_cache(cache_dir / "Locker_hashmap.json", {"Cached.zip": entry()}, age_hours = 25)
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker) == {"Game.zip": entry()}


def test_a_cache_from_the_future_is_rebuilt(cache_dir, tmp_path):
    write_cache(cache_dir / "Locker_hashmap.json", {"Cached.zip": entry()}, age_hours = -2)
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker) == {"Game.zip": entry()}


@pytest.mark.parametrize("contents", ["not json", "[1, 2]", '{"Game.zip": "aaaa"}', "null"])
def test_an_unreadable_cache_is_rebuilt(cache_dir, tmp_path, messages, contents):
    # Read as {}, a corrupt cache would make the locker look empty.
    write_cache(cache_dir / "Locker_hashmap.json", contents)
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker) == {"Game.zip": entry()}
    assert locker.listed


def test_a_cached_empty_map_is_used(cache_dir, tmp_path):
    write_cache(cache_dir / "Locker_hashmap.json", {})
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker) == {}


def test_a_cache_that_vanishes_is_rebuilt(cache_dir, tmp_path, monkeypatch):
    write_cache(cache_dir / "Locker_hashmap.json", {"Cached.zip": entry()})

    def vanished(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(lockersync.paths, "get_file_mod_time", vanished)
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry()})

    assert build(locker) == {"Game.zip": entry()}


###########################################################
# Remotes and their sidecars
###########################################################

def test_a_hashing_remote_is_listed_by_the_server(cache_dir):
    remote = FakeRemoteLocker(listing = {"Game.zip": entry()}, sidecar = {"Other.zip": entry()})

    assert build(remote) == {"Game.zip": entry()}
    assert remote.sidecar_reads == []


def test_a_remote_that_cannot_hash_reads_only_its_sidecar(cache_dir, messages):
    remote = FakeRemoteLocker(
        remote_type = config.RemoteType.SFTP,
        listing = {"Game.zip": entry("")}, sidecar = {"Game.zip": entry()})

    assert build(remote, verbose = True) == {"Game.zip": entry()}
    assert remote.listed == []


def test_a_failed_sidecar_read_is_a_failure(cache_dir, messages):
    remote = FakeRemoteLocker(remote_type = config.RemoteType.SFTP)
    remote.sidecar = None

    assert build(remote) is None


def test_a_listing_without_hashes_falls_back_to_the_sidecar(cache_dir, messages):
    remote = FakeRemoteLocker(listing = {"Game.zip": entry("")}, sidecar = {"Game.zip": entry("bbbb")})

    assert build(remote, verbose = True) == {"Game.zip": entry("bbbb")}
    assert any("Using sidecar hashes" in message for message in messages["info"])


def test_a_quiet_listing_without_hashes_falls_back_to_the_sidecar(cache_dir, messages):
    remote = FakeRemoteLocker(listing = {"Game.zip": entry("")}, sidecar = {"Game.zip": entry("bbbb")})

    assert build(remote) == {"Game.zip": entry("bbbb")}
    assert messages["info"] == []


def test_a_listing_without_hashes_stays_when_there_is_no_sidecar(cache_dir):
    remote = FakeRemoteLocker(listing = {"Game.zip": entry("")}, sidecar = {})

    assert build(remote) == {"Game.zip": entry("")}


def test_a_failed_fallback_sidecar_read_is_a_failure(cache_dir, messages):
    # The listing has no hashes to compare, so it cannot stand in.
    remote = FakeRemoteLocker(listing = {"Game.zip": entry("")})
    remote.sidecar = None

    assert build(remote) is None


def test_an_empty_remote_does_not_read_the_sidecar(cache_dir):
    # A stale sidecar would list files the remote no longer holds.
    remote = FakeRemoteLocker(listing = {}, sidecar = {"Gone.zip": entry()})

    assert build(remote) == {}
    assert remote.sidecar_reads == []


def test_a_failed_remote_listing_is_not_replaced_by_the_sidecar(cache_dir, messages):
    remote = FakeRemoteLocker(sidecar = {"Game.zip": entry()})
    remote.listing = None

    assert build(remote) is None
    assert remote.sidecar_reads == []


def test_a_local_locker_without_hashes_has_no_sidecar_to_read(cache_dir, tmp_path):
    locker = FakeLocalLocker(str(tmp_path), listing = {"Game.zip": entry("")})

    assert build(locker) == {"Game.zip": entry("")}
    assert locker.sidecar_reads == []
