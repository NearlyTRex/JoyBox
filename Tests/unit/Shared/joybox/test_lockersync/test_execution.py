# Imports
import pytest

# Local imports
from joybox import config, lockersync
from lockersync_helpers import FakeBackend, orphan_action, transfer_action


###########################################################
# Carrying out the plan
###########################################################

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
# Reporting progress
###########################################################

@pytest.mark.parametrize("action_type,label", [
    (config.SyncActionType.COPY, "Copying: "),
    (config.SyncActionType.UPDATE, "Updating: "),
    (config.SyncActionType.COPY_DECRYPT, "Copying (decrypt): "),
    (config.SyncActionType.UPDATE_ENCRYPT, "Updating (encrypt): "),
])
def test_a_verbose_transfer_names_what_it_does(messages, action_type, label):
    lockersync.execute_sync_actions(
        [transfer_action(action_type)], FakeBackend(), FakeBackend(), verbose = True)

    assert label + "Game.zip -> Game.zip" in messages["info"]


def test_a_verbose_recycle_names_the_file(messages):
    lockersync.execute_sync_actions([orphan_action()], FakeBackend(), FakeBackend(), verbose = True)

    assert "Recycling: Old.zip" in messages["info"]


def test_a_failed_recycle_fails_the_sync(messages):
    assert lockersync.execute_sync_actions(
        [orphan_action()], FakeBackend(), FakeBackend(result = False)) is False
    assert "Sync complete: 0 succeeded, 1 failed" in messages["info"]


def test_a_verbose_batched_recycle_names_the_file(messages):
    lockersync.execute_sync_actions_batched(
        [orphan_action()], FakeBackend(), FakeBackend(), verbose = True)

    assert "Recycling: Old.zip" in messages["info"]


def test_run_flags_reach_the_batch(messages):
    secondary = FakeBackend()
    lockersync.execute_sync_actions_batched(
        [transfer_action()], FakeBackend(), secondary,
        passphrase = "example", show_progress = True, pretend_run = True, exit_on_failure = True)

    passed = secondary.batched[0]["kwargs"]
    assert passed["passphrase"] == "example"
    assert passed["show_progress"] is True
    assert passed["pretend_run"] is True
    assert passed["exit_on_failure"] is True
