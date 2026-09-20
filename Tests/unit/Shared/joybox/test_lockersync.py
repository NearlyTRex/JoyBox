# Imports
import pytest

# Local imports
from joybox import config, lockersync


###########################################################
# Sync action selection
#
# The action type decides whether a file crosses between lockers encrypted,
# decrypted or untouched. Getting it wrong writes an unreadable file to the
# destination, or an unencrypted one to a remote that should be encrypted.
###########################################################

@pytest.mark.parametrize("base_action,expected", [
    ("COPY", config.SyncActionType.COPY),
    ("UPDATE", config.SyncActionType.UPDATE),
])
def test_matching_encryption_states_need_no_conversion(base_action, expected):
    assert lockersync.get_sync_action_type(base_action, False, False) == expected
    assert lockersync.get_sync_action_type(base_action, True, True) == expected


@pytest.mark.parametrize("base_action,expected", [
    ("COPY", config.SyncActionType.COPY_DECRYPT),
    ("UPDATE", config.SyncActionType.UPDATE_DECRYPT),
])
def test_encrypted_to_unencrypted_decrypts(base_action, expected):
    assert lockersync.get_sync_action_type(base_action, True, False) == expected


@pytest.mark.parametrize("base_action,expected", [
    ("COPY", config.SyncActionType.COPY_ENCRYPT),
    ("UPDATE", config.SyncActionType.UPDATE_ENCRYPT),
])
def test_unencrypted_to_encrypted_encrypts(base_action, expected):
    assert lockersync.get_sync_action_type(base_action, False, True) == expected


def test_every_encryption_pairing_is_handled():
    # Four combinations, each resolving to exactly one action.
    resolved = {
        (primary, secondary): lockersync.get_sync_action_type("COPY", primary, secondary)
        for primary in (True, False) for secondary in (True, False)
    }

    assert all(action is not None for action in resolved.values())
    assert resolved[(True, False)] != resolved[(False, True)]


def test_an_unknown_base_action_falls_back_to_update():
    # Only COPY is special-cased; anything else updates in place.
    assert lockersync.get_sync_action_type("SOMETHING", False, False) == \
        config.SyncActionType.UPDATE


###########################################################
# Action normalizing
###########################################################

@pytest.mark.parametrize("action_type", config.SyncActionType.members())
def test_every_action_type_normalizes_from_its_string(action_type):
    # Actions round-trip through the edited action file as plain text.
    assert lockersync.normalize_action_type({"type": action_type.val()}) == action_type


@pytest.mark.parametrize("action_type", config.SyncActionType.members())
def test_an_action_type_passes_through_unchanged(action_type):
    assert lockersync.normalize_action_type({"type": action_type}) == action_type


def test_an_unknown_action_type_normalizes_to_nothing():
    assert lockersync.normalize_action_type({"type": "not-an-action"}) is None


def test_a_missing_action_type_normalizes_to_nothing():
    assert lockersync.normalize_action_type({}) is None


###########################################################
# Action file content
###########################################################

def copy_action(path = "file.txt", action_type = None):
    return {"type": action_type or config.SyncActionType.COPY, "dest": path}


def update_action(path = "file.txt", action_type = None):
    return {"type": action_type or config.SyncActionType.UPDATE, "dest": path}


def recycle_action(path = "orphan.txt"):
    return {"type": config.SyncActionType.RECYCLE, "path": path}


def test_new_files_are_listed():
    content = lockersync.generate_action_file_content([copy_action("new.txt")], "Remote")

    assert "new.txt" in content
    assert "NEW FILES (1)" in content


def test_updated_files_are_listed_separately():
    content = lockersync.generate_action_file_content(
        [copy_action("new.txt"), update_action("changed.txt")], "Remote")

    assert "NEW FILES (1)" in content
    assert "UPDATED FILES (1)" in content


@pytest.mark.parametrize("action_type", [
    config.SyncActionType.COPY,
    config.SyncActionType.COPY_DECRYPT,
    config.SyncActionType.COPY_ENCRYPT,
])
def test_every_copy_variant_counts_as_a_new_file(action_type):
    content = lockersync.generate_action_file_content(
        [copy_action("new.txt", action_type)], "Remote")

    assert "NEW FILES (1)" in content


@pytest.mark.parametrize("action_type", [
    config.SyncActionType.UPDATE,
    config.SyncActionType.UPDATE_DECRYPT,
    config.SyncActionType.UPDATE_ENCRYPT,
])
def test_every_update_variant_counts_as_an_updated_file(action_type):
    content = lockersync.generate_action_file_content(
        [update_action("changed.txt", action_type)], "Remote")

    assert "UPDATED FILES (1)" in content


def test_orphans_are_listed_commented_out():
    # Recycling is destructive, so it is opt-in by uncommenting.
    content = lockersync.generate_action_file_content([recycle_action("gone.txt")], "Remote")

    for line in content.split("\n"):
        if "gone.txt" in line:
            assert line.lstrip().startswith("#")


def test_orphans_can_be_omitted():
    content = lockersync.generate_action_file_content(
        [recycle_action("gone.txt")], "Remote", include_orphans = False)

    assert "gone.txt" not in content


def test_the_target_name_heads_the_file():
    assert "MyRemote" in lockersync.generate_action_file_content(
        [copy_action()], "MyRemote")


def test_no_actions_produces_no_sections():
    content = lockersync.generate_action_file_content([], "Remote")

    assert "NEW FILES" not in content
    assert "UPDATED FILES" not in content


def test_an_action_falls_back_to_its_source_path():
    # Some actions carry only a source.
    content = lockersync.generate_action_file_content(
        [{"type": config.SyncActionType.COPY, "src": "source.txt"}], "Remote")

    assert "source.txt" in content


###########################################################
# Deciding what to sync
#
# The action list is the whole plan: a file left out is never copied, and a
# file wrongly marked an orphan is recycled out of the destination.
###########################################################

def entry(hash_value = "aaaa", size = 1024):
    return {"hash": hash_value, "size": size, "mtime": 1700000000}


def actions_for(primary, secondary, **kwargs):
    return lockersync.build_sync_actions(primary, secondary, **kwargs)


def types_of(actions):
    return [action["type"] for action in actions]


def test_a_file_only_on_the_primary_is_copied():
    actions = actions_for({"Game.zip": entry()}, {})

    assert types_of(actions) == [config.SyncActionType.COPY]
    assert actions[0]["src"] == "Game.zip"
    assert actions[0]["dest"] == "Game.zip"


def test_a_file_that_differs_is_updated():
    actions = actions_for({"Game.zip": entry("aaaa")}, {"Game.zip": entry("bbbb")})

    assert types_of(actions) == [config.SyncActionType.UPDATE]


def test_an_identical_file_is_left_alone():
    # Re-uploading an unchanged file is the expensive mistake this avoids.
    assert actions_for({"Game.zip": entry("aaaa")}, {"Game.zip": entry("aaaa")}) == []


def test_a_file_only_on_the_secondary_is_recycled():
    actions = actions_for({}, {"Old.zip": entry()})

    assert types_of(actions) == [config.SyncActionType.RECYCLE]
    assert actions[0]["path"] == "Old.zip"


def test_a_recycled_file_carries_the_data_it_was_found_with():
    actions = actions_for({}, {"Old.zip": entry("cccc")})

    assert actions[0]["src_data"]["hash"] == "cccc"


def test_a_file_already_in_the_recycle_bin_is_not_recycled_again():
    # Recycling the recycle bin into itself never terminates.
    assert actions_for({}, {".recycle_bin/Old.zip": entry()}) == []


def test_an_excluded_file_is_not_copied():
    assert actions_for({"Cache/junk.tmp": entry()}, {}, exclude_write_paths = ["Cache"]) == []


def test_an_excluded_orphan_is_not_recycled():
    # An excluded path was never synced, so its absence upstream means
    # nothing about whether it should stay.
    assert actions_for({}, {"Cache/junk.tmp": entry()}, exclude_write_paths = ["Cache"]) == []


def test_every_file_gets_its_own_action():
    actions = actions_for(
        {"New.zip": entry(), "Changed.zip": entry("aaaa"), "Same.zip": entry("same")},
        {"Changed.zip": entry("bbbb"), "Same.zip": entry("same"), "Gone.zip": entry()})

    assert sorted(types_of(actions)) == sorted([
        config.SyncActionType.COPY,
        config.SyncActionType.UPDATE,
        config.SyncActionType.RECYCLE,
    ])


def test_copying_to_an_encrypted_locker_encrypts():
    actions = actions_for({"Game.zip": entry()}, {}, secondary_encrypted = True)

    assert types_of(actions) == [config.SyncActionType.COPY_ENCRYPT]


def test_copying_from_an_encrypted_locker_decrypts():
    actions = actions_for({"Game.zip": entry()}, {}, primary_encrypted = True)

    assert types_of(actions) == [config.SyncActionType.COPY_DECRYPT]


def test_two_encrypted_lockers_need_no_conversion():
    actions = actions_for(
        {"Game.zip": entry()}, {},
        primary_encrypted = True, secondary_encrypted = True)

    assert types_of(actions) == [config.SyncActionType.COPY]


def test_nothing_on_either_side_is_no_work():
    assert actions_for({}, {}) == []


###########################################################
# Carrying out the plan
###########################################################

class FakeBackend:

    def __init__(self, result = True, root = "/locker"):
        self.result = result
        self.root = root
        self.synced = []
        self.batched = []
        self.recycled = []

    def get_root_path(self):
        return self.root

    def sync_from(self, src_backend, src_rel_path, dest_rel_path, **kwargs):
        self.synced.append({
            "src": src_rel_path,
            "dest": dest_rel_path,
            "cryption": kwargs.get("cryption_type"),
            "passphrase": kwargs.get("passphrase"),
        })
        return self.result

    def sync_batch_from(self, src_backend, actions, cryption_type, **kwargs):
        self.batched.append({"actions": actions, "cryption": cryption_type})
        paths = [action.get("src", "") for action in actions]
        if self.result:
            return (paths, [])
        return ([], paths)

    def recycle_file(self, rel_path, **kwargs):
        self.recycled.append(rel_path)
        return self.result


def transfer_action(action_type = None, src = "Game.zip"):
    return {
        "type": action_type or config.SyncActionType.COPY,
        "src": src,
        "dest": src,
        "src_data": entry(),
    }


def orphan_action(path = "Old.zip"):
    return {"type": config.SyncActionType.RECYCLE, "path": path, "src_data": entry()}


def test_a_copy_is_carried_out_against_the_destination():
    primary = FakeBackend()
    secondary = FakeBackend()

    assert lockersync.execute_sync_actions([transfer_action()], primary, secondary) is True
    assert secondary.synced[0]["src"] == "Game.zip"
    assert primary.synced == []


def test_an_orphan_is_recycled_on_the_destination():
    primary = FakeBackend()
    secondary = FakeBackend()

    lockersync.execute_sync_actions([orphan_action()], primary, secondary)

    assert secondary.recycled == ["Old.zip"]
    assert primary.recycled == []


@pytest.mark.parametrize("action_type,expected", [
    (config.SyncActionType.COPY, config.CryptionType.NONE),
    (config.SyncActionType.UPDATE, config.CryptionType.NONE),
    (config.SyncActionType.COPY_ENCRYPT, config.CryptionType.ENCRYPT),
    (config.SyncActionType.UPDATE_ENCRYPT, config.CryptionType.ENCRYPT),
    (config.SyncActionType.COPY_DECRYPT, config.CryptionType.DECRYPT),
    (config.SyncActionType.UPDATE_DECRYPT, config.CryptionType.DECRYPT),
])
def test_each_action_carries_its_own_cryption(action_type, expected):
    secondary = FakeBackend()

    lockersync.execute_sync_actions([transfer_action(action_type)], FakeBackend(), secondary)

    assert secondary.synced[0]["cryption"] == expected


def test_the_passphrase_reaches_the_transfer():
    secondary = FakeBackend()

    lockersync.execute_sync_actions(
        [transfer_action(config.SyncActionType.COPY_ENCRYPT)],
        FakeBackend(), secondary, passphrase = "example")

    assert secondary.synced[0]["passphrase"] == "example"


def test_an_action_type_stored_as_a_string_is_understood():
    # The plan round trips through an editor as text.
    secondary = FakeBackend()
    action = transfer_action()
    action["type"] = config.SyncActionType.COPY.val()

    lockersync.execute_sync_actions([action], FakeBackend(), secondary)

    assert len(secondary.synced) == 1


def test_a_failed_transfer_fails_the_sync():
    assert lockersync.execute_sync_actions(
        [transfer_action()], FakeBackend(), FakeBackend(result = False)) is False


def test_an_empty_plan_succeeds():
    assert lockersync.execute_sync_actions([], FakeBackend(), FakeBackend()) is True


def test_an_unknown_action_is_ignored():
    secondary = FakeBackend()

    assert lockersync.execute_sync_actions(
        [{"type": "NotAnAction", "src": "Game.zip"}], FakeBackend(), secondary) is True
    assert secondary.synced == []


###########################################################
# Carrying out the plan in batches
###########################################################

def test_files_of_one_cryption_go_out_as_a_single_transfer():
    # One rclone run per group instead of one per file is the whole point.
    secondary = FakeBackend()

    lockersync.execute_sync_actions_batched(
        [transfer_action(src = "One.zip"), transfer_action(src = "Two.zip")],
        FakeBackend(), secondary)

    assert len(secondary.batched) == 1
    assert len(secondary.batched[0]["actions"]) == 2


def test_each_cryption_gets_its_own_batch():
    secondary = FakeBackend()

    lockersync.execute_sync_actions_batched([
        transfer_action(config.SyncActionType.COPY, "Plain.zip"),
        transfer_action(config.SyncActionType.COPY_ENCRYPT, "Secret.zip"),
        transfer_action(config.SyncActionType.COPY_DECRYPT, "Readable.zip"),
    ], FakeBackend(), secondary)

    assert [batch["cryption"] for batch in secondary.batched] == [
        config.CryptionType.NONE,
        config.CryptionType.ENCRYPT,
        config.CryptionType.DECRYPT,
    ]


def test_an_empty_group_is_not_transferred():
    secondary = FakeBackend()

    lockersync.execute_sync_actions_batched([transfer_action()], FakeBackend(), secondary)

    assert len(secondary.batched) == 1


def test_a_batched_sync_reports_what_it_moved():
    success, moved = lockersync.execute_sync_actions_batched(
        [transfer_action(src = "One.zip")], FakeBackend(), FakeBackend())

    assert success is True
    assert moved == ["One.zip"]


def test_a_failed_batch_reports_failure():
    success, moved = lockersync.execute_sync_actions_batched(
        [transfer_action()], FakeBackend(), FakeBackend(result = False))

    assert success is False
    assert moved == []


def test_orphans_are_recycled_alongside_a_batch():
    # Recycling cannot be batched, so it still happens one file at a time.
    secondary = FakeBackend()

    success, moved = lockersync.execute_sync_actions_batched(
        [transfer_action(), orphan_action()], FakeBackend(), secondary)

    assert success is True
    assert secondary.recycled == ["Old.zip"]
    assert "Old.zip" in moved


def test_a_failed_recycle_fails_the_batched_sync():
    success, _ = lockersync.execute_sync_actions_batched(
        [orphan_action()], FakeBackend(), FakeBackend(result = False))

    assert success is False


def test_an_empty_batched_plan_succeeds():
    success, moved = lockersync.execute_sync_actions_batched([], FakeBackend(), FakeBackend())

    assert success is True
    assert moved == []


###########################################################
# The hash map cache
###########################################################

@pytest.fixture
def cache_dir(monkeypatch, tmp_path):
    target = tmp_path / "cache"
    monkeypatch.setattr(
        lockersync.environment, "get_cache_sync_dir", lambda: str(target))
    return target


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
