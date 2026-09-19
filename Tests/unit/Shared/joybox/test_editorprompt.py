# Imports
import pytest

# Local imports
from joybox import editorprompt


###########################################################
# Action files
#
# The user edits a generated list in their editor and what comes back drives
# copies, moves and deletions, so a line parsed wrongly acts on the wrong file
# and a comment parsed as an action acts when it should not.
###########################################################

def parse(text):
    return editorprompt.parse_action_lines(text)


###########################################################
# Parsing
###########################################################

def test_an_action_line_is_parsed():
    assert parse("UPLOAD /games/doom.zip") == [
        {"type": "UPLOAD", "path": "/games/doom.zip"}]


def test_several_lines_are_parsed():
    actions = parse("UPLOAD /a\nDOWNLOAD /b")

    assert [action["type"] for action in actions] == ["UPLOAD", "DOWNLOAD"]


def test_an_action_type_is_uppercased():
    assert parse("upload /a")[0]["type"] == "UPLOAD"


def test_a_path_keeps_its_case():
    assert parse("UPLOAD /Games/Doom.zip")[0]["path"] == "/Games/Doom.zip"


def test_a_path_with_spaces_is_kept_whole():
    # Game directories are full of spaces; splitting on all of them would
    # truncate the path at the first one.
    assert parse("UPLOAD /games/Final Fantasy VII/disc 1.cue")[0]["path"] == \
        "/games/Final Fantasy VII/disc 1.cue"


def test_surrounding_whitespace_is_stripped():
    assert parse("   UPLOAD   /a   ")[0] == {"type": "UPLOAD", "path": "/a"}


def test_extra_space_between_action_and_path_is_absorbed():
    assert parse("UPLOAD     /a")[0]["path"] == "/a"


def test_a_tab_separates_an_action_from_its_path():
    assert parse("UPLOAD\t/a")[0] == {"type": "UPLOAD", "path": "/a"}


###########################################################
# Skipped lines
###########################################################

def test_a_commented_line_is_skipped():
    # Destructive entries are generated commented out; uncommenting is the
    # opt in.
    assert parse("#UPLOAD /a") == []


def test_a_commented_line_with_a_space_is_skipped():
    assert parse("# UPLOAD /a") == []


def test_an_indented_comment_is_skipped():
    assert parse("   # UPLOAD /a") == []


def test_uncommenting_enables_an_action():
    assert parse("UPLOAD /a") == [{"type": "UPLOAD", "path": "/a"}]


def test_a_blank_line_is_skipped():
    assert parse("\n\nUPLOAD /a\n\n") == [{"type": "UPLOAD", "path": "/a"}]


def test_a_whitespace_only_line_is_skipped():
    assert parse("   \n\t\nUPLOAD /a") == [{"type": "UPLOAD", "path": "/a"}]


def test_an_action_without_a_path_is_skipped():
    # A bare verb names no target, so there is nothing safe to do with it.
    assert parse("UPLOAD") == []


def test_empty_content_parses_to_nothing():
    assert parse("") == []


def test_content_of_only_comments_parses_to_nothing():
    assert parse("# === Uploads ===\n# nothing to do\n") == []


def test_a_custom_comment_character_is_honoured():
    actions = editorprompt.parse_action_lines("//UPLOAD /a\nUPLOAD /b", comment_char = "//")

    assert actions == [{"type": "UPLOAD", "path": "/b"}]


def test_a_hash_is_not_a_comment_under_a_custom_character():
    actions = editorprompt.parse_action_lines("#UPLOAD /a", comment_char = "//")

    assert actions == [{"type": "#UPLOAD", "path": "/a"}]


###########################################################
# Source and destination
###########################################################

def test_an_arrow_line_is_parsed_as_a_pair():
    assert parse("RENAME /games/old.zip -> new.zip") == [
        {"type": "RENAME", "src": "/games/old.zip", "dest": "new.zip"}]


def test_an_arrow_pair_has_no_path_key():
    # Callers branch on which keys are present.
    action = parse("RENAME /a -> b")[0]

    assert "path" not in action
    assert sorted(action) == ["dest", "src", "type"]


def test_a_plain_line_has_no_source_or_destination():
    action = parse("UPLOAD /a")[0]

    assert "src" not in action and "dest" not in action


def test_arrow_sides_are_stripped():
    assert parse("RENAME  /a   ->   b  ")[0] == {"type": "RENAME", "src": "/a", "dest": "b"}


def test_only_the_first_arrow_splits():
    # A later arrow belongs to the destination name.
    assert parse("RENAME /a -> b -> c")[0] == {"type": "RENAME", "src": "/a", "dest": "b -> c"}


def test_paths_with_spaces_survive_an_arrow():
    action = parse("RENAME /games/Final Fantasy VII -> Final Fantasy 7")[0]

    assert action["src"] == "/games/Final Fantasy VII"
    assert action["dest"] == "Final Fantasy 7"


def test_a_bare_arrow_is_not_a_separator():
    # The separator carries its own spaces, so a hyphenated name is safe.
    assert parse("UPLOAD /games/re->make.zip")[0]["path"] == "/games/re->make.zip"


def test_a_custom_separator_is_honoured():
    actions = editorprompt.parse_action_lines("RENAME /a => b", arrow_separator = " => ")

    assert actions == [{"type": "RENAME", "src": "/a", "dest": "b"}]


###########################################################
# Generating
###########################################################

def test_a_section_lists_its_items():
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": ["UPLOAD /a", "UPLOAD /b"]}])

    assert "UPLOAD /a" in text
    assert "UPLOAD /b" in text


def test_a_section_is_titled():
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": ["UPLOAD /a"]}])

    assert "# === Uploads ===" in text


def test_a_section_description_is_commented():
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": ["UPLOAD /a"], "description": "Sent to the remote"}])

    assert "# Sent to the remote" in text


def test_header_lines_are_commented():
    text = editorprompt.generate_action_file(
        [{"title": "Uploads", "items": ["UPLOAD /a"]}],
        header_lines = ["Edit this file", "Save to continue"])

    assert text.startswith("# Edit this file\n# Save to continue\n")


def test_an_empty_section_is_omitted():
    # A heading with nothing under it is noise in the editor.
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": []},
        {"title": "Downloads", "items": ["DOWNLOAD /a"]}])

    assert "Uploads" not in text
    assert "Downloads" in text


def test_no_sections_generate_nothing():
    assert editorprompt.generate_action_file([]) == ""


def test_a_commented_section_comments_every_item():
    text = editorprompt.generate_action_file([
        {"title": "Deletions", "items": ["DELETE /a", "DELETE /b"], "commented": True}])

    assert "#DELETE /a" in text
    assert "#DELETE /b" in text


def test_an_uncommented_section_leaves_items_bare():
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": ["UPLOAD /a"]}])

    assert "\nUPLOAD /a\n" in text


def test_a_custom_comment_character_is_used_throughout():
    text = editorprompt.generate_action_file(
        [{"title": "Deletions", "items": ["DELETE /a"], "commented": True}],
        header_lines = ["Edit me"],
        comment_char = "//")

    assert "// Edit me" in text
    assert "// === Deletions ===" in text
    assert "//DELETE /a" in text
    assert "#" not in text


###########################################################
# Round trip
###########################################################

def test_a_generated_file_parses_back_to_its_items():
    text = editorprompt.generate_action_file(
        [{"title": "Uploads", "items": ["UPLOAD /a", "DOWNLOAD /b"]}],
        header_lines = ["Edit this file"])

    assert parse(text) == [
        {"type": "UPLOAD", "path": "/a"},
        {"type": "DOWNLOAD", "path": "/b"},
    ]


def test_a_commented_section_parses_back_to_nothing():
    text = editorprompt.generate_action_file([
        {"title": "Deletions", "items": ["DELETE /a"], "commented": True}])

    assert parse(text) == []


def test_only_the_uncommented_sections_come_back():
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": ["UPLOAD /a"]},
        {"title": "Deletions", "items": ["DELETE /b"], "commented": True},
    ])

    assert parse(text) == [{"type": "UPLOAD", "path": "/a"}]


def test_a_generated_arrow_item_round_trips():
    text = editorprompt.generate_action_file([
        {"title": "Renames", "items": ["RENAME /games/old.zip -> new.zip"]}])

    assert parse(text) == [
        {"type": "RENAME", "src": "/games/old.zip", "dest": "new.zip"}]


def test_a_generated_path_with_spaces_round_trips():
    text = editorprompt.generate_action_file([
        {"title": "Uploads", "items": ["UPLOAD /games/Final Fantasy VII/disc 1.cue"]}])

    assert parse(text)[0]["path"] == "/games/Final Fantasy VII/disc 1.cue"


def test_a_custom_comment_character_round_trips():
    text = editorprompt.generate_action_file(
        [
            {"title": "Uploads", "items": ["UPLOAD /a"]},
            {"title": "Deletions", "items": ["DELETE /b"], "commented": True},
        ],
        header_lines = ["Edit me"],
        comment_char = "//")

    assert editorprompt.parse_action_lines(text, comment_char = "//") == [
        {"type": "UPLOAD", "path": "/a"}]
