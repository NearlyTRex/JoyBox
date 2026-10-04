# Imports
import pytest

# Local imports
from joybox import audible


###########################################################
# Activation bytes
#
# The 8 hex character key that decrypts an AAX audiobook. It is pulled out of
# whatever the user pasted or saved, so the extraction has to find it inside
# surrounding text and refuse anything that is not exactly eight hex digits.
###########################################################

def test_bare_activation_bytes_are_extracted():
    assert audible.extract_activation_bytes("1a2b3c4d") == "1a2b3c4d"


def test_uppercase_activation_bytes_are_extracted():
    assert audible.extract_activation_bytes("1A2B3C4D") == "1A2B3C4D"


def test_case_is_preserved():
    # ffmpeg takes the value verbatim.
    assert audible.extract_activation_bytes("AbCdEf01") == "AbCdEf01"


def test_digits_only_are_extracted():
    assert audible.extract_activation_bytes("12345678") == "12345678"


def test_letters_only_are_extracted():
    assert audible.extract_activation_bytes("abcdefab") == "abcdefab"


###########################################################
# Surrounding text
###########################################################

@pytest.mark.parametrize("text", [
    "1a2b3c4d\n",
    "  1a2b3c4d  ",
    "activation_bytes: 1a2b3c4d",
    "Your activation bytes are 1a2b3c4d, keep them safe.",
    "1a2b3c4d is the key",
    "key=1a2b3c4d",
    "[1a2b3c4d]",
    "line one\n1a2b3c4d\nline three",
])
def test_activation_bytes_are_found_in_surrounding_text(text):
    assert audible.extract_activation_bytes(text) == "1a2b3c4d"


def test_the_first_match_wins():
    assert audible.extract_activation_bytes("1a2b3c4d and deadbeef") == "1a2b3c4d"


###########################################################
# Rejected input
###########################################################

@pytest.mark.parametrize("text", [
    None,
    "",
    "   ",
    "no key here",
    "1a2b3c",
    "1a2b3c4",
    "xxxxxxxx",
    "1a2b3c4g",
    "the quick brown fox",
])
def test_input_without_activation_bytes_yields_nothing(text):
    assert audible.extract_activation_bytes(text) is None


def test_a_longer_hex_run_is_not_a_match():
    # A nine digit run is not a key, and taking eight of it would hand ffmpeg a
    # silently truncated value.
    assert audible.extract_activation_bytes("1a2b3c4d5") is None


def test_a_longer_hex_run_beside_a_real_key_does_not_win():
    assert audible.extract_activation_bytes("1a2b3c4d5e 1a2b3c4d") == "1a2b3c4d"


def test_a_hex_run_inside_a_word_is_not_a_match():
    assert audible.extract_activation_bytes("prefix1a2b3c4dsuffix") is None


@pytest.mark.parametrize("separator", ["-", ":", "/", "."])
def test_a_key_bounded_by_punctuation_is_found(separator):
    assert audible.extract_activation_bytes(
        "key%s1a2b3c4d%send" % (separator, separator)) == "1a2b3c4d"


###########################################################
# Lookup order
###########################################################

@pytest.fixture
def no_ambient_sources(monkeypatch, tmp_path):
    # An unrelated key in the user's real settings, environment or home
    # directory would otherwise decide these.
    monkeypatch.setattr(audible.settings, "get_value", lambda *args, **kwargs: None)
    monkeypatch.delenv("AUDIBLE_ACTIVATION_BYTES", raising = False)
    monkeypatch.setattr(audible.runtime, "get_home_directory", lambda: str(tmp_path))
    return tmp_path


def test_the_settings_value_is_preferred(monkeypatch, no_ambient_sources):
    monkeypatch.setattr(audible.settings, "get_value", lambda *args, **kwargs: "1a2b3c4d")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes() == "1a2b3c4d"


def test_an_authcode_file_is_read(no_ambient_sources, tmp_path):
    target = tmp_path / "authcode.txt"
    target.write_text("activation_bytes: 1a2b3c4d\n")

    assert audible.get_activation_bytes(str(target)) == "1a2b3c4d"


def test_an_authcode_file_beats_the_environment(monkeypatch, no_ambient_sources, tmp_path):
    target = tmp_path / "authcode.txt"
    target.write_text("1a2b3c4d")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(target)) == "1a2b3c4d"


def test_the_environment_is_used_when_nothing_else_has_a_key(monkeypatch, no_ambient_sources):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes() == "deadbeef"


def test_the_home_directory_file_is_the_last_resort(no_ambient_sources, tmp_path):
    (tmp_path / ".audible_authcode").write_text("1a2b3c4d\n")

    assert audible.get_activation_bytes() == "1a2b3c4d"


def test_a_missing_authcode_file_falls_through(monkeypatch, no_ambient_sources, tmp_path):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(tmp_path / "absent.txt")) == "deadbeef"


def test_a_source_holding_no_key_falls_through(monkeypatch, no_ambient_sources, tmp_path):
    # An empty or placeholder file must not stop the search.
    target = tmp_path / "authcode.txt"
    target.write_text("paste your key here\n")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(target)) == "deadbeef"


def test_no_source_yields_nothing(no_ambient_sources):
    assert audible.get_activation_bytes() is None


def test_a_settings_value_holding_no_key_falls_through(monkeypatch, no_ambient_sources):
    monkeypatch.setattr(audible.settings, "get_value", lambda *args, **kwargs: "unset")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes() == "deadbeef"


def test_an_empty_authcode_file_falls_through(monkeypatch, no_ambient_sources, tmp_path):
    target = tmp_path / "authcode.txt"
    target.write_text("")
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.get_activation_bytes(str(target)) == "deadbeef"


def test_an_environment_value_holding_no_key_falls_through(monkeypatch, no_ambient_sources, tmp_path):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "unset")
    (tmp_path / ".audible_authcode").write_text("1a2b3c4d")

    assert audible.get_activation_bytes() == "1a2b3c4d"


@pytest.mark.parametrize("contents", ["", "paste your key here"])
def test_a_home_file_holding_no_key_yields_nothing(no_ambient_sources, tmp_path, contents):
    (tmp_path / ".audible_authcode").write_text(contents)

    assert audible.get_activation_bytes() is None


###########################################################
# Decrypting one file
#
# ffmpeg is never run; the command it would have been given is recorded.
###########################################################

KEY_BYTES = "1a2b3c4d"


@pytest.fixture
def ffmpeg(monkeypatch, no_ambient_sources):
    from fakes import RecordingCommand
    state = {"installed": True}
    monkeypatch.setattr(audible.programs, "is_tool_installed", lambda name: state["installed"])
    monkeypatch.setattr(audible.programs, "get_tool_program", lambda name: "/bin/ffmpeg")
    state["command"] = RecordingCommand(monkeypatch)
    return state


@pytest.fixture
def book(tmp_path):
    target = tmp_path / "book.aax"
    target.write_bytes(b"aax")
    return str(target)


def test_a_book_is_decrypted_beside_itself(ffmpeg, book):
    assert audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES) is True
    assert ffmpeg["command"].only() == [
        "/bin/ffmpeg", "-activation_bytes", KEY_BYTES, "-i", book,
        "-c", "copy", "-n", book[:-4] + ".m4a"]


def test_overwriting_is_passed_to_ffmpeg(ffmpeg, book, tmp_path):
    output = tmp_path / "out" / "book.m4a"
    output.parent.mkdir()
    output.write_bytes(b"old")

    assert audible.decrypt_aax_to_m4a(
        book, str(output), activation_bytes = KEY_BYTES, overwrite = True) is True
    assert "-y" in ffmpeg["command"].only()


def test_an_existing_output_is_skipped(ffmpeg, book, tmp_path):
    output = tmp_path / "book.m4a"
    output.write_bytes(b"old")

    assert audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES) is True
    assert ffmpeg["command"].ran() is False


def test_the_output_directory_is_created(ffmpeg, book, tmp_path):
    output = tmp_path / "new" / "book.m4a"

    assert audible.decrypt_aax_to_m4a(book, str(output), activation_bytes = KEY_BYTES) is True
    assert output.parent.is_dir()


def test_an_output_without_a_directory_is_written_in_place(ffmpeg, book):
    assert audible.decrypt_aax_to_m4a(book, "book.m4a", activation_bytes = KEY_BYTES) is True
    assert ffmpeg["command"].only()[-1] == "book.m4a"


def test_the_key_is_looked_up_when_not_given(ffmpeg, book, monkeypatch):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.decrypt_aax_to_m4a(book) is True
    assert ffmpeg["command"].value_after("-activation_bytes") == "deadbeef"


def test_a_pretend_run_does_not_run_ffmpeg(ffmpeg, book):
    assert audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES, pretend_run = True) is True
    assert ffmpeg["command"].ran() is False


@pytest.fixture
def failing_ffmpeg(ffmpeg):
    ffmpeg["command"].returncode = 1
    return ffmpeg


def test_a_failed_ffmpeg_run_is_a_failure(failing_ffmpeg, book):
    assert audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES) is False


def test_a_failed_ffmpeg_run_can_exit(failing_ffmpeg, book):
    with pytest.raises(SystemExit):
        audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES, exit_on_failure = True)


def missing_input(tmp_path):
    return str(tmp_path / "absent.aax")


def wrong_extension(tmp_path):
    target = tmp_path / "book.mp3"
    target.write_bytes(b"mp3")
    return str(target)


@pytest.mark.parametrize("make_input", [missing_input, wrong_extension])
@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_an_unusable_input_is_refused(ffmpeg, tmp_path, make_input, exit_on_failure):
    source = make_input(tmp_path)
    if exit_on_failure:
        with pytest.raises(SystemExit):
            audible.decrypt_aax_to_m4a(source, activation_bytes = KEY_BYTES, exit_on_failure = True)
    else:
        assert audible.decrypt_aax_to_m4a(source, activation_bytes = KEY_BYTES) is False
    assert ffmpeg["command"].ran() is False


def test_an_aa_book_is_accepted(ffmpeg, tmp_path):
    target = tmp_path / "BOOK.AA"
    target.write_bytes(b"aa")

    assert audible.decrypt_aax_to_m4a(str(target), activation_bytes = KEY_BYTES) is True


@pytest.mark.parametrize("key", [None, "1a2b3c4", "1a2b3c4g"])
@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_a_missing_or_malformed_key_is_refused(ffmpeg, book, key, exit_on_failure):
    if exit_on_failure:
        with pytest.raises(SystemExit):
            audible.decrypt_aax_to_m4a(book, activation_bytes = key, exit_on_failure = True)
    else:
        assert audible.decrypt_aax_to_m4a(book, activation_bytes = key) is False
    assert ffmpeg["command"].ran() is False


@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_a_missing_ffmpeg_is_refused(ffmpeg, book, exit_on_failure):
    ffmpeg["installed"] = False
    if exit_on_failure:
        with pytest.raises(SystemExit):
            audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES, exit_on_failure = True)
    else:
        assert audible.decrypt_aax_to_m4a(book, activation_bytes = KEY_BYTES) is False


###########################################################
# Decrypting several files
###########################################################

@pytest.fixture
def decrypted(monkeypatch):
    state = {"calls": [], "fail": set()}

    def decrypt_aax_to_m4a(input_file, output_file = None, **kwargs):
        state["calls"].append((input_file, output_file, kwargs))
        return input_file not in state["fail"]
    monkeypatch.setattr(audible, "decrypt_aax_to_m4a", decrypt_aax_to_m4a)
    return state


def test_every_file_is_decrypted_into_the_output_directory(decrypted):
    assert audible.decrypt_aax_files_to_m4a(
        ["/in/a.aax", "/in/b.aa"], output_dir = "/out", activation_bytes = KEY_BYTES) is True
    assert [call[1] for call in decrypted["calls"]] == ["/out/a.m4a", "/out/b.m4a"]
    assert decrypted["calls"][0][2]["activation_bytes"] == KEY_BYTES
    assert decrypted["calls"][0][2]["exit_on_failure"] is False


def test_without_an_output_directory_each_file_is_decrypted_in_place(decrypted):
    audible.decrypt_aax_files_to_m4a(["/in/a.aax"], activation_bytes = KEY_BYTES)

    assert decrypted["calls"][0][1] is None


def test_the_key_is_looked_up_once_for_the_batch(decrypted, monkeypatch, no_ambient_sources):
    monkeypatch.setenv("AUDIBLE_ACTIVATION_BYTES", "deadbeef")

    assert audible.decrypt_aax_files_to_m4a(["/in/a.aax"]) is True
    assert decrypted["calls"][0][2]["activation_bytes"] == "deadbeef"


def test_one_failure_fails_the_batch(decrypted):
    decrypted["fail"] = {"/in/a.aax"}

    assert audible.decrypt_aax_files_to_m4a(
        ["/in/a.aax", "/in/b.aax"], activation_bytes = KEY_BYTES) is False
    assert len(decrypted["calls"]) == 2


def test_a_failure_can_stop_the_batch(decrypted):
    decrypted["fail"] = {"/in/a.aax"}

    with pytest.raises(SystemExit):
        audible.decrypt_aax_files_to_m4a(
            ["/in/a.aax", "/in/b.aax"], activation_bytes = KEY_BYTES, exit_on_failure = True)
    assert len(decrypted["calls"]) == 1


@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_an_empty_batch_is_refused(decrypted, exit_on_failure):
    if exit_on_failure:
        with pytest.raises(SystemExit):
            audible.decrypt_aax_files_to_m4a([], exit_on_failure = True)
    else:
        assert audible.decrypt_aax_files_to_m4a([]) is False


@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_a_batch_without_a_key_is_refused(decrypted, no_ambient_sources, exit_on_failure):
    if exit_on_failure:
        with pytest.raises(SystemExit):
            audible.decrypt_aax_files_to_m4a(["/in/a.aax"], exit_on_failure = True)
    else:
        assert audible.decrypt_aax_files_to_m4a(["/in/a.aax"]) is False
    assert decrypted["calls"] == []


###########################################################
# Decrypting a directory
###########################################################

@pytest.fixture
def library(tmp_path, monkeypatch):
    root = tmp_path / "books"
    (root / "series").mkdir(parents = True)
    (root / "one.aax").write_bytes(b"")
    (root / "two.AA").write_bytes(b"")
    (root / "cover.jpg").write_bytes(b"")
    (root / "series" / "three.aax").write_bytes(b"")
    batches = []

    def decrypt_aax_files_to_m4a(input_files, output_dir = None, **kwargs):
        batches.append((sorted(input_files), output_dir))
        return True
    monkeypatch.setattr(audible, "decrypt_aax_files_to_m4a", decrypt_aax_files_to_m4a)
    return {"root": str(root), "batches": batches}


def test_the_books_in_a_directory_are_decrypted_in_place(library):
    root = library["root"]

    assert audible.decrypt_aax_directory(root) is True
    assert library["batches"] == [
        (sorted([root + "/one.aax", root + "/two.AA"]), root)]


def test_a_recursive_search_includes_subdirectories(library, tmp_path):
    root = library["root"]
    output = str(tmp_path / "out")

    assert audible.decrypt_aax_directory(root, output_dir = output, recursive = True) is True
    assert library["batches"][0][0] == sorted([
        root + "/one.aax", root + "/two.AA", root + "/series/three.aax"])
    assert library["batches"][0][1] == output
    assert (tmp_path / "out").is_dir()


def test_a_directory_without_books_is_not_a_failure(library, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    assert audible.decrypt_aax_directory(str(empty)) is True
    assert library["batches"] == []


@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_a_missing_directory_is_refused(library, tmp_path, exit_on_failure):
    missing = str(tmp_path / "absent")
    if exit_on_failure:
        with pytest.raises(SystemExit):
            audible.decrypt_aax_directory(missing, exit_on_failure = True)
    else:
        assert audible.decrypt_aax_directory(missing) is False
