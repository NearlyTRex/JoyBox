# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config, lockersync
from lockersync_helpers import FakeBackend, FakeLocalLocker, FakeLockerInfo, FakeRemoteLocker, entry


###########################################################
# Checking the lockers can be reached
###########################################################

@pytest.fixture
def configured(monkeypatch):
    state = {"configured": True}
    monkeypatch.setattr(
        lockersync.sync, "is_remote_configured", lambda name, remote_type: state["configured"])
    return state


def test_reachable_lockers_pass(tmp_path, configured):
    assert lockersync.verify_prerequisites(
        FakeLocalLocker(str(tmp_path)), [FakeRemoteLocker(), FakeLocalLocker(str(tmp_path))]) is True


@pytest.mark.parametrize("root", [None, "absent"])
def test_a_missing_local_primary_fails(tmp_path, messages, root):
    primary = FakeLocalLocker(None if root is None else str(tmp_path / root))

    assert lockersync.verify_prerequisites(primary, []) is False


def test_an_unconfigured_remote_primary_fails(configured, messages):
    configured["configured"] = False

    assert lockersync.verify_prerequisites(FakeRemoteLocker(), []) is False


@pytest.mark.parametrize("root", [None, "absent"])
def test_a_missing_local_secondary_fails(tmp_path, messages, root):
    secondary = FakeLocalLocker(None if root is None else str(tmp_path / root))

    assert lockersync.verify_prerequisites(FakeLocalLocker(str(tmp_path)), [secondary]) is False


def test_an_unconfigured_remote_secondary_fails(tmp_path, configured, messages):
    configured["configured"] = False

    assert lockersync.verify_prerequisites(
        FakeLocalLocker(str(tmp_path)), [FakeRemoteLocker()]) is False


def test_a_backend_of_another_kind_is_not_checked(tmp_path):
    assert lockersync.verify_prerequisites(FakeBackend(), [FakeBackend()]) is True


###########################################################
# Syncing lockers end to end
#
# Lockers and their backends are stood in for, so the whole plan can be run
# and checked: what was transferred, what was recycled, what the cache says
# afterwards, and whether the run reports the truth about failures.
###########################################################

class Lockers:

    def __init__(self, monkeypatch, tmp_path):
        self.tmp_path = tmp_path
        self.infos = {}
        self.backends = {}
        monkeypatch.setattr(lockersync.lockerinfo, "LockerInfo", lambda locker_type: self.infos[locker_type])
        monkeypatch.setattr(
            lockersync.lockerbackend, "get_backend_for_locker", lambda info: self.backends[info.name])
        monkeypatch.setattr(lockersync.sync, "is_remote_configured", lambda name, remote_type: True)

    def local(self, name, listing = None, **kwargs):
        root = self.tmp_path / name
        root.mkdir(exist_ok = True)
        return self.add(name, FakeLocalLocker(str(root), listing = listing), **kwargs)

    def remote(self, name, listing = None, remote_type = config.RemoteType.DRIVE, **kwargs):
        return self.add(name, FakeRemoteLocker(remote_type = remote_type, listing = listing), **kwargs)

    def add(self, name, backend, **kwargs):
        self.infos[name] = FakeLockerInfo(name, **kwargs)
        self.backends[name] = backend
        return backend


@pytest.fixture
def lockers(monkeypatch, tmp_path, cache_dir, messages):
    return Lockers(monkeypatch, tmp_path)


def run(primary, secondaries, **kwargs):
    kwargs.setdefault("interactive", False)
    return lockersync.sync_lockers(primary, secondaries, **kwargs)


def cached(name, excludes):
    with open(lockersync.get_cache_file(name, excludes)) as handle:
        return json.load(handle)


SECONDARY_EXCLUDES = [".recycle_bin/**"]


def test_missing_files_are_copied_to_each_secondary(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    first = lockers.remote("Gdrive")
    second = lockers.local("External")

    assert run("Local", ["Gdrive", "External"]) is True
    assert first.batched[0]["actions"][0]["src"] == "Game.zip"
    assert second.batched[0]["actions"][0]["src"] == "Game.zip"


def test_unreachable_lockers_sync_nothing(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.local("External")
    secondary.root_path = None

    assert run("Local", ["External"]) is False
    assert secondary.batched == []


def test_a_failed_primary_listing_fails_the_sync(lockers):
    lockers.local("Local").listing = None
    secondary = lockers.remote("Gdrive")

    assert run("Local", ["Gdrive"]) is False
    assert secondary.listed == []


def test_an_empty_primary_is_refused(lockers):
    # Every file on the secondaries would be an orphan.
    lockers.local("Local", {})
    secondary = lockers.remote("Gdrive", {"Game.zip": entry()})

    assert run("Local", ["Gdrive"], recycle_orphans = True) is False
    assert secondary.recycled == []


def test_a_failed_secondary_listing_fails_the_sync_but_not_the_others(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Gdrive").listing = None
    second = lockers.local("External")

    assert run("Local", ["Gdrive", "External"]) is False
    assert len(second.batched) == 1


def test_a_failed_secondary_listing_stops_at_once_when_asked(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Gdrive").listing = None
    second = lockers.local("External")

    assert run("Local", ["Gdrive", "External"], exit_on_failure = True) is False
    assert second.listed == []


def test_secondary_listings_leave_out_excludes_and_the_recycle_bin(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive", excluded_dirs = ["Cache/**"])
    run("Local", ["Gdrive"])

    assert secondary.listed[0]["excludes"] == ["Cache/**", ".recycle_bin/**"]


def test_a_secondary_in_step_needs_nothing(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive", {"Game.zip": entry()})

    assert run("Local", ["Gdrive"]) is True
    assert secondary.batched == []


def test_orphans_are_kept_unless_recycling_is_asked_for(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive", {"Game.zip": entry(), "Old.zip": entry()})

    assert run("Local", ["Gdrive"]) is True
    assert secondary.recycled == []


def test_orphans_are_recycled_when_asked(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive", {"Game.zip": entry(), "Old.zip": entry()})

    assert run("Local", ["Gdrive"], recycle_orphans = True) is True
    assert secondary.recycled == ["Old.zip"]


def test_a_failed_transfer_fails_the_sync_but_not_the_others(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Gdrive").result = False
    second = lockers.local("External")

    assert run("Local", ["Gdrive", "External"]) is False
    assert len(second.batched) == 1


def test_a_failed_transfer_stops_at_once_when_asked(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Gdrive").result = False
    second = lockers.local("External")

    assert run("Local", ["Gdrive", "External"], exit_on_failure = True) is False
    assert second.listed == []


def test_run_flags_reach_the_transfer(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive")
    run("Local", ["Gdrive"], verbose = True, pretend_run = True)

    assert secondary.batched[0]["kwargs"]["pretend_run"] is True
    assert secondary.batched[0]["kwargs"]["verbose"] is True


PRIMARY_PHRASE = "primary phrase"
SECONDARY_PHRASE = "secondary phrase"


@pytest.mark.parametrize("primary_encrypted,secondary_encrypted,expected", [
    (True, False, PRIMARY_PHRASE),
    (False, True, SECONDARY_PHRASE),
    (True, True, None),
    (False, False, None),
])
def test_the_passphrase_follows_the_direction_of_encryption(
        lockers, primary_encrypted, secondary_encrypted, expected):
    lockers.local("Local", {"Game.zip": entry()},
                  encrypted = primary_encrypted, passphrase = PRIMARY_PHRASE)
    secondary = lockers.remote("Gdrive", encrypted = secondary_encrypted, passphrase = SECONDARY_PHRASE)
    run("Local", ["Gdrive"])

    assert secondary.batched[0]["kwargs"]["passphrase"] == expected


###########################################################
# The cache after a sync
###########################################################

def test_uploaded_files_are_recorded_in_the_secondary_cache(lockers):
    # Otherwise a re-run within the cache window uploads them again.
    lockers.local("Local", {"Game.zip": entry("new")})
    lockers.remote("Gdrive", {"Game.zip": entry("old"), "Other.zip": entry()})
    run("Local", ["Gdrive"])

    assert cached("Gdrive", SECONDARY_EXCLUDES)["Game.zip"] == entry("new")


def test_recycled_files_leave_the_secondary_cache(lockers):
    # Left in, the next run within the cache window recycles them again.
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Gdrive", {"Game.zip": entry(), "Old.zip": entry()})
    run("Local", ["Gdrive"], recycle_orphans = True)

    assert "Old.zip" not in cached("Gdrive", SECONDARY_EXCLUDES)


def test_a_rerun_within_the_cache_window_does_nothing(lockers):
    lockers.local("Local", {"Game.zip": entry("new")})
    secondary = lockers.remote("Gdrive", {"Game.zip": entry("old"), "Old.zip": entry()})
    run("Local", ["Gdrive"], recycle_orphans = True)
    secondary.batched.clear()
    secondary.recycled.clear()

    assert run("Local", ["Gdrive"], recycle_orphans = True) is True
    assert secondary.batched == []
    assert secondary.recycled == []


def test_a_pretend_run_leaves_the_secondary_cache_as_listed(lockers):
    lockers.local("Local", {"Game.zip": entry("new")})
    lockers.remote("Gdrive", {"Game.zip": entry("old")})
    run("Local", ["Gdrive"], pretend_run = True)

    assert cached("Gdrive", SECONDARY_EXCLUDES)["Game.zip"] == entry("old")


def test_a_failed_transfer_is_not_recorded_in_the_cache(lockers):
    lockers.local("Local", {"Game.zip": entry("new")})
    lockers.remote("Gdrive", {"Game.zip": entry("old")}).result = False
    run("Local", ["Gdrive"])

    assert cached("Gdrive", SECONDARY_EXCLUDES)["Game.zip"] == entry("old")


def test_recycling_a_path_the_map_never_held_leaves_the_cache_alone(lockers, monkeypatch):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Gdrive", {"Game.zip": entry()})
    monkeypatch.setattr(lockersync, "build_sync_actions", lambda **kwargs: [
        {"type": config.SyncActionType.RECYCLE, "path": "Vanished.zip"}])
    writes = []
    monkeypatch.setattr(
        lockersync.serialization, "write_json_file", lambda **kwargs: writes.append(kwargs["src"]))

    assert run("Local", ["Gdrive"], recycle_orphans = True) is True
    assert len(writes) == 2


###########################################################
# Approving the plan in an editor
###########################################################

def test_an_edited_plan_carries_out_only_what_was_kept(lockers, monkeypatch):
    lockers.local("Local", {"Keep.zip": entry(), "Drop.zip": entry()})
    secondary = lockers.remote("Gdrive")
    monkeypatch.setattr(
        lockersync.editorprompt, "open_editor",
        lambda content, **kwargs: content.replace("COPY Drop.zip", "# COPY Drop.zip"))

    assert run("Local", ["Gdrive"], interactive = True) is True
    assert [action["src"] for action in secondary.batched[0]["actions"]] == ["Keep.zip"]


def test_a_renamed_upload_is_not_recorded_under_a_name_the_primary_lacks(lockers, monkeypatch):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive", {"Other.zip": entry()})
    monkeypatch.setattr(
        lockersync.editorprompt, "open_editor",
        lambda content, **kwargs: content.replace("COPY Game.zip", "COPY Game.zip -> Renamed.zip"))

    assert run("Local", ["Gdrive"], interactive = True) is True
    assert secondary.batched[0]["actions"][0]["dest"] == "Renamed.zip"
    assert "Renamed.zip" not in cached("Gdrive", SECONDARY_EXCLUDES)


def test_a_cancelled_editor_syncs_nothing(lockers, monkeypatch):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive")
    monkeypatch.setattr(lockersync.editorprompt, "open_editor", lambda content, **kwargs: None)

    assert run("Local", ["Gdrive"], interactive = True) is True
    assert secondary.batched == []


def test_an_emptied_plan_syncs_nothing(lockers, monkeypatch):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive")
    monkeypatch.setattr(lockersync.editorprompt, "open_editor", lambda content, **kwargs: "")

    assert run("Local", ["Gdrive"], interactive = True) is True
    assert secondary.batched == []


###########################################################
# Refreshing the sidecar
###########################################################

def test_a_sidecar_remote_is_refreshed_from_the_local_primary(lockers):
    primary = lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Hetzner", remote_type = config.RemoteType.SFTP, excluded_dirs = ["Cache/**"])

    assert run("Local", ["Hetzner"]) is True
    assert secondary.sidecar_updates[0]["local_root_path"] == primary.get_root_path()
    assert secondary.sidecar_updates[0]["excludes"] == ["Cache/**"]


def test_a_failed_sidecar_refresh_fails_the_sync(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Hetzner", remote_type = config.RemoteType.SFTP).sidecar_result = False
    second = lockers.local("External")

    assert run("Local", ["Hetzner", "External"]) is False
    assert len(second.batched) == 1


def test_a_failed_sidecar_refresh_stops_at_once_when_asked(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    lockers.remote("Hetzner", remote_type = config.RemoteType.SFTP).sidecar_result = False
    second = lockers.local("External")

    assert run("Local", ["Hetzner", "External"], exit_on_failure = True) is False
    assert second.listed == []


def test_a_sidecar_is_not_refreshed_after_a_failed_transfer(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Hetzner", remote_type = config.RemoteType.SFTP)
    secondary.result = False
    run("Local", ["Hetzner"])

    assert secondary.sidecar_updates == []


def test_a_sidecar_refresh_can_be_skipped(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Hetzner", remote_type = config.RemoteType.SFTP)
    run("Local", ["Hetzner"], rebuild_sidecars = False)

    assert secondary.sidecar_updates == []


def test_a_hashing_remote_has_no_sidecar_to_refresh(lockers):
    lockers.local("Local", {"Game.zip": entry()})
    secondary = lockers.remote("Gdrive")
    run("Local", ["Gdrive"])

    assert secondary.sidecar_updates == []


def test_a_remote_primary_does_not_refresh_sidecars(lockers):
    # Only local content is known to be the plaintext the sidecar describes.
    lockers.remote("Gdrive", {"Game.zip": entry()})
    secondary = lockers.remote("Hetzner", remote_type = config.RemoteType.SFTP)
    run("Gdrive", ["Hetzner"])

    assert secondary.sidecar_updates == []
