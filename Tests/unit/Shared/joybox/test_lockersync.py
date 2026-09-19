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
