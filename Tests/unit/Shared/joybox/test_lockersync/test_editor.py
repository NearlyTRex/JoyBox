# Imports
import pytest

# Local imports
from joybox import config, lockersync
from lockersync_helpers import entry, orphan_action, transfer_action


###########################################################
# Reading back the edited plan
#
# The editor only chooses among the proposed actions. What comes back is a
# list of text lines, so each must be matched to the action it names, with
# that action's full details, before anything is transferred.
###########################################################

def edit(actions, edited_text, monkeypatch):
    shown = {}

    def open_editor(content, **kwargs):
        shown["content"] = content
        return edited_text(content)

    monkeypatch.setattr(lockersync.editorprompt, "open_editor", open_editor)
    approved = lockersync.open_editor_for_sync_actions(actions, "Remote")
    return approved, shown["content"]


def test_an_unchanged_plan_approves_every_transfer(monkeypatch):
    actions = [transfer_action(src = "One.zip"), transfer_action(config.SyncActionType.UPDATE, "Two.zip")]

    approved, _ = edit(actions, lambda content: content, monkeypatch)

    assert approved == actions


def test_an_approved_action_keeps_its_details(monkeypatch):
    # The transfer needs the source and destination, not just the shown path.
    action = transfer_action(config.SyncActionType.COPY_ENCRYPT, "Games/Game.zip")

    approved, _ = edit([action], lambda content: content, monkeypatch)

    assert approved[0]["src"] == "Games/Game.zip"
    assert approved[0]["dest"] == "Games/Game.zip"
    assert approved[0]["src_data"] == entry()


def test_orphans_stay_unapproved_unless_uncommented(monkeypatch):
    actions = [transfer_action(), orphan_action("Old.zip")]

    approved, _ = edit(actions, lambda content: content, monkeypatch)

    assert approved == [actions[0]]


def test_an_uncommented_orphan_is_approved(monkeypatch):
    actions = [orphan_action("Old.zip")]

    approved, _ = edit(actions, lambda content: content.replace("#RECYCLE", "RECYCLE"), monkeypatch)

    assert approved == actions


def test_a_deleted_line_is_not_approved(monkeypatch):
    actions = [transfer_action(src = "One.zip"), transfer_action(src = "Two.zip")]

    approved, _ = edit(actions, lambda content: content.replace("COPY Two.zip", ""), monkeypatch)

    assert [action["src"] for action in approved] == ["One.zip"]


def test_a_path_with_spaces_is_matched(monkeypatch):
    actions = [transfer_action(src = "My Games/Some Game.zip")]

    approved, _ = edit(actions, lambda content: content, monkeypatch)

    assert approved == actions


def test_an_arrow_gives_a_new_destination(monkeypatch):
    actions = [transfer_action(src = "Game.zip")]

    approved, _ = edit(
        actions, lambda content: content.replace("COPY Game.zip", "COPY Game.zip -> Renamed.zip"), monkeypatch)

    assert approved[0]["src"] == "Game.zip"
    assert approved[0]["dest"] == "Renamed.zip"
    assert actions[0]["dest"] == "Game.zip"


@pytest.mark.parametrize("line", ["COPY Other.zip", "UPDATE Game.zip", "RECYCLE Game.zip", "BOGUS Game.zip"])
def test_a_line_that_was_not_proposed_is_ignored(monkeypatch, messages, line):
    # The editor cannot invent work, or retype it into something destructive.
    actions = [transfer_action(src = "Game.zip")]

    approved, _ = edit(actions, lambda content: line, monkeypatch)

    assert approved == []
    assert messages["warning"]


def test_a_cancelled_editor_approves_nothing(monkeypatch):
    monkeypatch.setattr(lockersync.editorprompt, "open_editor", lambda content, **kwargs: None)

    assert lockersync.open_editor_for_sync_actions([transfer_action()], "Remote") is None


def test_the_action_type_is_matched_whatever_its_case(monkeypatch):
    actions = [transfer_action(config.SyncActionType.UPDATE_DECRYPT, "Game.zip")]

    approved, content = edit(actions, lambda content: content.replace("UPDATEDECRYPT", "updatedecrypt"), monkeypatch)

    assert "UPDATEDECRYPT Game.zip" in content
    assert approved == actions
