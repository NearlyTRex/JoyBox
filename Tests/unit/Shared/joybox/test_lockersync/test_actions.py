# Imports
import pytest

# Local imports
from joybox import config, lockersync
from lockersync_helpers import entry


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


@pytest.mark.parametrize("primary_encrypted,secondary_encrypted,expected", [
    (False, False, config.SyncActionType.UPDATE),
    (True, True, config.SyncActionType.UPDATE),
    (True, False, config.SyncActionType.UPDATE_DECRYPT),
    (False, True, config.SyncActionType.UPDATE_ENCRYPT),
])
def test_an_unknown_base_action_falls_back_to_update(primary_encrypted, secondary_encrypted, expected):
    # Only COPY is special-cased; anything else updates in place, still
    # converting between encrypted and plain lockers.
    assert lockersync.get_sync_action_type("SOMETHING", primary_encrypted, secondary_encrypted) == expected


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
# The recycle bin
#
# Only the recycle folder itself is left alone, matched on whole path parts:
# a folder that merely starts with the same letters is ordinary content.
###########################################################

@pytest.mark.parametrize("path", [".recycle_bin", ".recycle_bin/Old.zip", ".recycle_bin/deep/Old.zip"])
def test_the_primary_recycle_bin_is_not_copied(path):
    assert actions_for({path: entry()}, {}) == []


@pytest.mark.parametrize("path", [".recycle_binary/Old.zip", ".recycle_bin_old/Old.zip", "Games/.recycle_bin/Old.zip"])
def test_a_folder_that_only_looks_like_the_recycle_bin_is_recycled(path):
    assert types_of(actions_for({}, {path: entry()})) == [config.SyncActionType.RECYCLE]


def test_a_folder_that_only_looks_like_the_recycle_bin_is_copied():
    assert types_of(actions_for({".recycle_binary/Game.zip": entry()}, {})) == [config.SyncActionType.COPY]
