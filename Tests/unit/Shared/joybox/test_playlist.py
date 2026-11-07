# Third-party imports
import pytest

# Local imports
from joybox import playlist


###########################################################
# Playlist
#
# Multi-disc games are launched through an m3u, so a playlist that silently
# comes out empty or in the wrong order breaks disc swapping.
###########################################################

def touch(directory, *names):
    created = []
    for name in names:
        target = directory / name
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_text("data")
        created.append(target)
    return created


def lines(path):
    with open(str(path), encoding = "utf8") as handle:
        return [line.strip() for line in handle if line.strip()]


###########################################################
# Reading and writing
###########################################################

def test_a_playlist_is_written(tmp_path):
    target = tmp_path / "game.m3u"

    assert playlist.write_playlist(str(target), ["Disc 1.cue", "Disc 2.cue"]) is True
    assert lines(target) == ["Disc 1.cue", "Disc 2.cue"]


def test_every_entry_ends_with_a_newline(tmp_path):
    # Players read the file line by line; an unterminated last entry is dropped
    # by some of them.
    target = tmp_path / "game.m3u"
    playlist.write_playlist(str(target), ["Disc 1.cue"])

    assert target.read_text(encoding = "utf8") == "Disc 1.cue\n"


def test_a_playlist_is_read(tmp_path):
    target = tmp_path / "game.m3u"
    target.write_text("Disc 1.cue\nDisc 2.cue\n", encoding = "utf8")

    assert playlist.read_playlist(str(target)) == ["Disc 1.cue", "Disc 2.cue"]


def test_reading_strips_surrounding_whitespace(tmp_path):
    # Hand-edited playlists pick up trailing spaces and CRLF endings.
    target = tmp_path / "game.m3u"
    target.write_text("  Disc 1.cue  \r\nDisc 2.cue\n", encoding = "utf8")

    assert playlist.read_playlist(str(target)) == ["Disc 1.cue", "Disc 2.cue"]


def test_a_playlist_round_trips(tmp_path):
    target = str(tmp_path / "game.m3u")
    entries = ["Disc 1.cue", "Disc 2.cue", "Disc 3.cue"]
    playlist.write_playlist(target, entries)

    assert playlist.read_playlist(target) == entries


def test_a_missing_playlist_reads_as_empty(tmp_path):
    assert playlist.read_playlist(str(tmp_path / "absent.m3u")) == []


def test_an_empty_playlist_reads_as_empty(tmp_path):
    target = tmp_path / "game.m3u"
    target.write_text("", encoding = "utf8")

    assert playlist.read_playlist(str(target)) == []


def test_a_unicode_entry_round_trips(tmp_path):
    target = str(tmp_path / "game.m3u")
    playlist.write_playlist(target, ["Ys - Ancient Ys Vanished Ⅱ.cue"])

    assert playlist.read_playlist(target) == ["Ys - Ancient Ys Vanished Ⅱ.cue"]


def test_writing_to_an_unwritable_path_reports_failure(tmp_path):
    assert playlist.write_playlist(str(tmp_path / "missing" / "game.m3u"), ["x"]) is False


def test_pretending_does_not_write_a_playlist(tmp_path):
    target = tmp_path / "game.m3u"

    assert playlist.write_playlist(str(target), ["x"], pretend_run = True) is True
    assert not target.exists()


def test_pretending_does_not_read_a_playlist(tmp_path):
    target = tmp_path / "game.m3u"
    target.write_text("Disc 1.cue\n", encoding = "utf8")

    assert playlist.read_playlist(str(target), pretend_run = True) == []


###########################################################
# Generating
###########################################################

def test_matching_files_are_collected(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert [entry.split("/")[-1] for entry in lines(target)] == ["Disc 1.cue", "Disc 2.cue"]


def test_unmatched_extensions_are_left_out(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue", "Disc 1.bin", "readme.txt")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert [entry.split("/")[-1] for entry in lines(target)] == ["Disc 1.cue", "Disc 2.cue"]


def test_an_uppercase_extension_is_matched(tmp_path):
    # Dumps vary in case; the recursive path already matches either, so the
    # local path must too or the same directory yields a playlist one way and
    # nothing the other.
    touch(tmp_path, "Disc 1.CUE", "Disc 2.CUE")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert len(lines(target)) == 2


def test_an_extension_is_matched_case_insensitively_either_way(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".CUE"])

    assert len(lines(target)) == 2


def test_a_file_matching_two_extensions_is_listed_once(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue", ".CUE"])

    assert len(lines(target)) == 2


def test_multiple_extensions_are_all_collected(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.chd")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue", ".chd"])

    assert len(lines(target)) == 2


def test_no_extensions_collects_nothing(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [])

    assert not target.exists()


def test_entries_are_sorted_by_length_then_name(tmp_path):
    # Disc 10 must not sort ahead of Disc 2, which plain alphabetical order
    # would do.
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue", "Disc 10.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(
        str(tmp_path), str(target), extensions = [".cue"], only_keep_ends = True)

    assert lines(target) == ["Disc 1.cue", "Disc 2.cue", "Disc 10.cue"]


def test_only_keeping_ends_writes_bare_filenames(tmp_path):
    # An m3u beside the discs must reference them relatively or it breaks when
    # the library moves.
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(
        str(tmp_path), str(target), extensions = [".cue"], only_keep_ends = True)

    assert lines(target) == ["Disc 1.cue", "Disc 2.cue"]


def test_full_paths_are_written_by_default(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert sorted(lines(target)) == [str(tmp_path / "Disc 1.cue"), str(tmp_path / "Disc 2.cue")]


def test_subdirectories_are_ignored_without_recursion(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    touch(tmp_path, "extras/Bonus.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert len(lines(target)) == 2


def test_a_directory_is_never_collected_as_an_entry(tmp_path):
    touch(tmp_path, "Disc 1.cue", "Disc 2.cue")
    (tmp_path / "saves.cue").mkdir()
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert len(lines(target)) == 2


def test_a_missing_source_directory_writes_nothing(tmp_path):
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(str(tmp_path / "absent"), str(target), extensions = [".cue"])

    assert not target.exists()


###########################################################
# List size gates
###########################################################

def test_an_empty_result_writes_no_playlist(tmp_path):
    # A stale empty m3u is worse than none; the launcher would load it.
    touch(tmp_path, "readme.txt")
    target = tmp_path / "game.m3u"

    assert playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"]) is True
    assert not target.exists()


def test_a_single_entry_writes_no_playlist(tmp_path):
    # A one-disc game does not need swapping.
    touch(tmp_path, "Disc 1.cue")
    target = tmp_path / "game.m3u"

    assert playlist.generate_playlist(str(tmp_path), str(target), extensions = [".cue"]) is True
    assert not target.exists()


def test_a_single_entry_is_written_when_allowed(tmp_path):
    touch(tmp_path, "Disc 1.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(
        str(tmp_path), str(target), extensions = [".cue"], allow_single_lists = True)

    assert len(lines(target)) == 1


def test_an_empty_playlist_is_written_when_allowed(tmp_path):
    touch(tmp_path, "readme.txt")
    target = tmp_path / "game.m3u"
    playlist.generate_playlist(
        str(tmp_path), str(target), extensions = [".cue"], allow_empty_lists = True)

    assert target.exists()
    assert lines(target) == []


###########################################################
# Tree playlists
###########################################################

def test_a_tree_playlist_spans_subdirectories(tmp_path):
    touch(tmp_path, "disc1/Disc 1.cue", "disc2/Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_tree_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert len(lines(target)) == 2


def test_a_tree_playlist_keeps_full_paths(tmp_path):
    touch(tmp_path, "disc1/Disc 1.cue", "disc2/Disc 2.cue")
    target = tmp_path / "game.m3u"
    playlist.generate_tree_playlist(str(tmp_path), str(target), extensions = [".cue"])

    assert sorted(lines(target)) == [str(tmp_path / "disc1" / "Disc 1.cue"), str(tmp_path / "disc2" / "Disc 2.cue")]


def test_a_tree_playlist_honours_the_size_gates(tmp_path):
    touch(tmp_path, "disc1/Disc 1.cue")
    target = tmp_path / "game.m3u"

    assert playlist.generate_tree_playlist(str(tmp_path), str(target), extensions = [".cue"]) is True
    assert not target.exists()


def test_a_tree_and_a_local_scan_agree_on_a_flat_directory(tmp_path):
    touch(tmp_path, "Disc 1.CUE", "Disc 2.CUE")
    tree_target = tmp_path / "tree.m3u"
    local_target = tmp_path / "local.m3u"
    playlist.generate_tree_playlist(str(tmp_path), str(tree_target), extensions = [".cue"])
    playlist.generate_playlist(str(tmp_path), str(local_target), extensions = [".cue"])

    assert lines(tree_target) == lines(local_target)


###########################################################
# Local playlists
###########################################################

def test_a_playlist_is_written_into_each_game_directory(tmp_path):
    touch(tmp_path, "Game A/Disc 1.cue", "Game A/Disc 2.cue")
    touch(tmp_path, "Game B/Disc 1.cue", "Game B/Disc 2.cue")

    assert playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"]) is True
    assert lines(tmp_path / "Game A" / "Game A.m3u") == ["Disc 1.cue", "Disc 2.cue"]
    assert lines(tmp_path / "Game B" / "Game B.m3u") == ["Disc 1.cue", "Disc 2.cue"]


def test_a_local_playlist_is_named_after_its_directory(tmp_path):
    touch(tmp_path, "Final Fantasy VII/Disc 1.cue", "Final Fantasy VII/Disc 2.cue")
    playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"])

    assert (tmp_path / "Final Fantasy VII" / "Final Fantasy VII.m3u").exists()


def test_a_single_disc_directory_gets_no_playlist(tmp_path):
    touch(tmp_path, "Game A/Disc 1.cue")
    playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"])

    assert list((tmp_path / "Game A").iterdir()) == [tmp_path / "Game A" / "Disc 1.cue"]


def test_a_directory_without_matching_files_gets_no_playlist(tmp_path):
    touch(tmp_path, "Game A/readme.txt")
    playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"])

    assert not any(path.suffix == ".m3u" for path in (tmp_path / "Game A").iterdir())


def test_local_playlists_reach_nested_directories(tmp_path):
    touch(tmp_path, "PSX/Game A/Disc 1.cue", "PSX/Game A/Disc 2.cue")
    playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"])

    assert (tmp_path / "PSX" / "Game A" / "Game A.m3u").exists()


def test_local_playlists_match_an_uppercase_extension(tmp_path):
    touch(tmp_path, "Game A/Disc 1.CUE", "Game A/Disc 2.CUE")
    playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"])

    assert lines(tmp_path / "Game A" / "Game A.m3u") == ["Disc 1.CUE", "Disc 2.CUE"]


def test_an_empty_tree_produces_no_playlists(tmp_path):
    assert playlist.generate_local_playlists(str(tmp_path), extensions = [".cue"]) is True
    assert list(tmp_path.iterdir()) == []


###########################################################
# Logging and failure handling
###########################################################

def test_verbose_reads_and_writes_are_logged(tmp_path, monkeypatch):
    logged = []
    monkeypatch.setattr(playlist.logger, "log_info", logged.append)
    target = tmp_path / "game.m3u"
    playlist.write_playlist(str(target), ["disc1.chd"], verbose = True)
    playlist.read_playlist(str(target), verbose = True)

    assert len(logged) == 2
    assert all(str(target) in message for message in logged)


def test_an_unreadable_playlist_quits_when_asked_to(tmp_path):
    with pytest.raises(SystemExit):
        playlist.read_playlist(str(tmp_path / "absent.m3u"), exit_on_failure = True)


def test_an_unwritable_playlist_quits_when_asked_to(tmp_path):
    with pytest.raises(SystemExit):
        playlist.write_playlist(str(tmp_path / "absent" / "game.m3u"), ["disc1.chd"], exit_on_failure = True)


def test_a_tree_playlist_can_keep_only_filenames(tmp_path):
    touch(tmp_path, "a/disc1.chd", "b/disc2.chd")
    output = tmp_path / "all.m3u"
    playlist.generate_playlist(str(tmp_path), str(output), extensions = [".chd"], recursive = True, only_keep_ends = True)

    assert sorted(lines(output)) == ["disc1.chd", "disc2.chd"]


def test_a_failed_local_playlist_stops_the_run(tmp_path, monkeypatch):
    touch(tmp_path, "Game/disc1.chd", "Game/disc2.chd")
    monkeypatch.setattr(playlist, "write_playlist", lambda **kwargs: False)

    assert playlist.generate_local_playlists(str(tmp_path), extensions = [".chd"]) is False


###########################################################
# Disc playlists
#
# Numbered or labelled disc images get a playlist named after the game, so the json
# builder picks it as the game file and disc swapping works.
###########################################################

def disc_playlist(directory, name = "Game"):
    return playlist.generate_disc_playlist(str(directory), name)


def test_numbered_discs_get_a_playlist(tmp_path):
    touch(tmp_path, "Game (Disc 1).chd", "Game (Disc 2).chd")

    assert disc_playlist(tmp_path) is True
    assert lines(tmp_path / "Game.m3u") == ["Game (Disc 1).chd", "Game (Disc 2).chd"]


def test_discs_are_listed_by_number_not_by_name(tmp_path):
    # Sorted as text, disc 10 would come before disc 2.
    touch(tmp_path, *["Game (Disc %d).chd" % number for number in range(1, 11)])

    disc_playlist(tmp_path)

    assert lines(tmp_path / "Game.m3u") == ["Game (Disc %d).chd" % number for number in range(1, 11)]


@pytest.mark.parametrize("first,second", [
    ("Game (Disk 1).cue", "Game (Disk 2).cue"),
    ("Game (Disc 1 of 2).iso", "Game (Disc 2 of 2).iso"),
    ("Game (disc 1).gdi", "Game (disc 2).gdi"),
])
def test_other_numbering_styles_are_recognised(tmp_path, first, second):
    touch(tmp_path, first, second)

    disc_playlist(tmp_path)

    assert lines(tmp_path / "Game.m3u") == [first, second]


@pytest.mark.parametrize("names,expected", [
    (["Game (Bonus Disc).iso", "Game (Game Disc).iso"], ["Game (Game Disc).iso", "Game (Bonus Disc).iso"]),
    (["Game (Video Disc).chd", "Game (Bonus Disc).chd", "Game (Game Disc).chd"],
     ["Game (Game Disc).chd", "Game (Bonus Disc).chd", "Game (Video Disc).chd"]),
    (["Game (Disc B).cue", "Game (Disc A).cue"], ["Game (Disc A).cue", "Game (Disc B).cue"]),
    (["Game (Bonus Disc).chd", "Game (Disc 2).chd", "Game (Disc 1).chd"],
     ["Game (Disc 1).chd", "Game (Disc 2).chd", "Game (Bonus Disc).chd"]),
])
def test_labelled_discs_get_a_playlist(tmp_path, names, expected):
    # Redump names some sets by role instead of number; the game disc boots first.
    touch(tmp_path, *names)

    disc_playlist(tmp_path)

    assert lines(tmp_path / "Game.m3u") == expected


def test_a_disc_marker_needs_parentheses(tmp_path):
    touch(tmp_path, "Demo Disc Volume 1.iso", "Demo Disc Volume 2.iso")

    disc_playlist(tmp_path)

    assert not (tmp_path / "Game.m3u").exists()


def test_track_files_are_left_out(tmp_path):
    # The cue sheet names its own tracks; the playlist lists only the sheets.
    touch(tmp_path, "Game (Disc 1).cue", "Game (Disc 1).bin", "Game (Disc 2).cue", "Game (Disc 2).bin")

    disc_playlist(tmp_path)

    assert lines(tmp_path / "Game.m3u") == ["Game (Disc 1).cue", "Game (Disc 2).cue"]


def test_an_existing_playlist_is_kept(tmp_path):
    touch(tmp_path, "Game (Disc 1).chd", "Game (Disc 2).chd")
    (tmp_path / "Custom.m3u").write_text("Game (Disc 2).chd\n", encoding = "utf8")

    disc_playlist(tmp_path)

    assert not (tmp_path / "Game.m3u").exists()
    assert lines(tmp_path / "Custom.m3u") == ["Game (Disc 2).chd"]


@pytest.mark.parametrize("names", [
    ["Game (Disc 1).chd"],
    ["Game.chd", "Other.chd"],
    ["Game (Disc 1).zip", "Game (Disc 2).zip"],
    [],
])
def test_no_playlist_without_several_numbered_discs(tmp_path, names):
    touch(tmp_path, *names)

    assert disc_playlist(tmp_path) is True
    assert not (tmp_path / "Game.m3u").exists()


def test_only_discs_at_the_top_level_count(tmp_path):
    # Sub-folders hold dlc, updates and extras, not the game's own discs.
    touch(tmp_path, "Extra/Bonus (Disc 1).chd", "Extra/Bonus (Disc 2).chd")
    (tmp_path / "Folder (Disc 3).chd").mkdir()

    disc_playlist(tmp_path)

    assert not (tmp_path / "Game.m3u").exists()


def test_two_images_for_one_disc_make_no_playlist(tmp_path, caplog):
    # Which image to list is a guess, so it is left to the user.
    touch(tmp_path, "Game (Disc 1).chd", "Game (Disc 1).iso", "Game (Disc 2).chd")

    assert disc_playlist(tmp_path) is True
    assert not (tmp_path / "Game.m3u").exists()
    assert "share a disc" in caplog.text


def test_a_dry_run_writes_no_disc_playlist(tmp_path):
    touch(tmp_path, "Game (Disc 1).chd", "Game (Disc 2).chd")

    assert playlist.generate_disc_playlist(str(tmp_path), "Game", pretend_run = True) is True
    assert not (tmp_path / "Game.m3u").exists()
