# Third-party imports
import pytest

# Local imports
from joybox import chunkers


SAMPLE = "one\ntwo\nthree\nfour\nfive\n"


@pytest.fixture
def sample_file(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(SAMPLE)
    return str(target)


###########################################################
# Range parsing
#
# These come straight off the llm_chat command line, so a misparse quietly
# sends the wrong part of a file to the model.
###########################################################

@pytest.mark.parametrize("spec,expected", [
    ("10", (10, 10)),
    ("5-20", (5, 20)),
    ("-20", (0, 20)),
    ("5-", (5, 0)),
    ("", (0, 0)),
    (None, (0, 0)),
])
def test_ranges_parse(spec, expected):
    assert chunkers.parse_range(spec) == expected


@pytest.mark.parametrize("spec", ["abc", "1-x", "x-1"])
def test_a_malformed_range_raises(spec):
    # Raising lets the caller report the bad input instead of silently
    # defaulting to the whole file.
    with pytest.raises(ValueError):
        chunkers.parse_range(spec)


###########################################################
# Slicing
###########################################################

def test_a_slice_carries_line_numbers(sample_file):
    sliced = chunkers.slice_lines(sample_file, 2, 3, header = False)

    assert "2  two" in sliced
    assert "3  three" in sliced


def test_a_slice_excludes_lines_outside_the_range(sample_file):
    sliced = chunkers.slice_lines(sample_file, 2, 3, header = False)

    assert "one" not in sliced
    assert "four" not in sliced


def test_a_slice_past_the_end_is_empty(sample_file):
    assert chunkers.slice_lines(sample_file, 99, 100, header = False) == ""


def test_an_end_past_the_file_is_clamped(sample_file):
    sliced = chunkers.slice_lines(sample_file, 4, 999, header = False)

    assert "four" in sliced
    assert "five" in sliced


def test_a_zero_start_begins_at_the_first_line(sample_file):
    sliced = chunkers.slice_lines(sample_file, 0, 2, header = False)

    assert "1  one" in sliced


def test_a_zero_end_runs_to_the_last_line(sample_file):
    sliced = chunkers.slice_lines(sample_file, 4, 0, header = False)

    assert "five" in sliced


def test_the_header_names_the_file_and_range(sample_file):
    sliced = chunkers.slice_lines(sample_file, 2, 3)

    assert "sample.py" in sliced
    assert "lines 2-3 of 5" in sliced


def test_the_header_opens_a_fence_for_the_extension(sample_file):
    assert "```py" in chunkers.slice_lines(sample_file, 1, 2)


def test_a_file_without_an_extension_fences_as_text(tmp_path):
    target = tmp_path / "noext"
    target.write_text(SAMPLE)

    assert "```text" in chunkers.slice_lines(str(target), 1, 2)


###########################################################
# Rendering
###########################################################

def test_a_rendered_file_holds_every_line(sample_file):
    rendered = chunkers.render_file(sample_file)

    for line in ["one", "two", "three", "four", "five"]:
        assert line in rendered


def test_a_rendered_file_reports_its_length(sample_file):
    assert "5 lines" in chunkers.render_file(sample_file)


def test_a_rendered_file_is_fenced(sample_file):
    rendered = chunkers.render_file(sample_file)

    assert rendered.count("```") == 2


###########################################################
# Chunker selection
###########################################################

def test_chunkers_are_registered():
    names = [name for name, _ in chunkers.list_chunkers()]

    assert "python" in names
    assert "lines" in names


def test_an_extension_selects_its_chunker(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def thing():\n    pass\n")

    assert chunkers.get_chunker(str(target)).name == "python"


def test_an_unknown_extension_falls_back(tmp_path):
    target = tmp_path / "sample.unknown"
    target.write_text("content\n")

    assert chunkers.get_chunker(str(target)).name == "lines"


def test_chunker_selection_ignores_case(tmp_path):
    target = tmp_path / "SAMPLE.PY"
    target.write_text("def thing():\n    pass\n")

    assert chunkers.get_chunker(str(target)).name == "python"


###########################################################
# Outlines and regions
###########################################################

def test_an_outline_finds_python_structure(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    pass\n\ndef beta():\n    pass\n")

    outline = chunkers.outline(str(target), header = False)

    assert "alpha" in outline
    assert "beta" in outline


def test_an_outline_reports_when_there_is_no_structure(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("x = 1\ny = 2\n")

    assert "no structure found" in chunkers.outline(str(target), header = False)


def test_an_outline_header_names_the_chunker(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    pass\n")

    assert "python chunker" in chunkers.outline(str(target))


def test_a_named_region_is_sliced(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    return 1\n\ndef beta():\n    return 2\n")

    region = chunkers.slice_region(str(target), "alpha")

    assert "return 1" in region


def test_an_unknown_region_yields_nothing(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    pass\n")

    assert chunkers.slice_region(str(target), "nonexistent") == ""


def test_regions_are_listed(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    pass\n\ndef beta():\n    pass\n")

    listed = chunkers.list_regions(str(target))

    assert any("alpha" in name for name in listed)


###########################################################
# Token estimation
###########################################################

def test_an_estimate_scales_with_length():
    assert chunkers.estimate_tokens("x" * 360) > chunkers.estimate_tokens("x" * 36)


def test_an_empty_string_estimates_zero():
    assert chunkers.estimate_tokens("") == 0


def test_an_estimate_is_a_whole_number():
    assert isinstance(chunkers.estimate_tokens("some text here"), int)


def test_a_reversed_range_is_empty(sample_file):
    assert chunkers.slice_lines(sample_file, 4, 2) == ""


def test_an_empty_file_slices_to_nothing(tmp_path):
    target = tmp_path / "empty.py"
    target.write_text("")

    assert chunkers.slice_lines(str(target)) == ""


###########################################################
# Base chunker
###########################################################

def test_the_base_chunker_finds_no_marks():
    assert chunkers.Chunker().marks(["anything"]) == []


def test_a_region_runs_to_the_next_mark():
    lines = ["def alpha():", "    pass", "def beta():", "    pass", ""]

    regions = chunkers.PythonChunker().regions(lines)

    assert regions == {"def_alpha": (1, 2), "def_beta": (3, 5)}


def test_colliding_region_names_stay_addressable():
    lines = ["def alpha():", "    pass", "def alpha():", "    pass"]

    regions = chunkers.PythonChunker().regions(lines)

    assert regions == {"def_alpha": (1, 2), "def_alpha_3": (3, 4)}


def test_a_label_without_word_characters_is_named_by_line():
    assert chunkers.Chunker().region_name("!!!", 7) == "line_7"


def test_a_long_region_name_is_truncated():
    assert len(chunkers.Chunker().region_name("x" * 100, 1)) == 48


def test_a_short_map_is_not_thinned():
    found = [(n, "x") for n in range(chunkers.MAX_MARKS)]

    assert chunkers.Chunker().thin(found) == found


def test_a_long_map_is_thinned_to_the_limit():
    found = [(n, "x") for n in range(chunkers.MAX_MARKS * 3 + 5)]

    thinned = chunkers.Chunker().thin(found)

    assert len(thinned) <= chunkers.MAX_MARKS
    assert thinned[0] == found[0]


###########################################################
# Assembly chunker
###########################################################

def asm_marks(text):
    return chunkers.AsmChunker().marks(text.splitlines())


def test_asm_marks_where_code_begins_after_the_header():
    marks = asm_marks("; void f(void)\n; locals\n\n    PUSH EBP\n")

    assert marks == [(4, "-- code begins --")]


def test_asm_first_code_line_keeps_its_own_label():
    marks = asm_marks("; header\nFUN_00401000:\n    RET\n")

    assert marks == [(2, "FUN_00401000")]


def test_asm_finds_labels_xrefs_and_targets():
    text = ("    PUSH EBP\n"
            "LAB_0040100a:\n"
            "    ; XREF[1]: LAB_00401020\n"
            "    CALL FUN_00402000\n"
            "    JMP SHORT LAB_0040100a\n"
            "    MOV EAX, 1\n")

    assert asm_marks(text) == [
        (1, "-- code begins --"),
        (2, "LAB_0040100a"),
        (3, "LAB_00401020"),
        (4, "-> FUN_00402000"),
        (5, "-> LAB_0040100a"),
    ]


def test_asm_targets_are_found_in_lowercase_mnemonics():
    assert asm_marks("main:\n    call printf\n")[1] == (2, "-> printf")


@pytest.mark.parametrize("line", ["CALL dword ptr [EBP + -0x8]", "jmp qword [rax]", "CALL PTR"])
def test_asm_indirect_targets_are_not_marked(line):
    assert asm_marks(f"main:\n    {line}\n") == [(1, "main")]


###########################################################
# C chunker
###########################################################

def c_marks(text):
    return chunkers.CChunker().marks(text.splitlines())


def test_c_finds_header_comments_types_and_functions():
    text = ("// Name: FUN_00401000\n"
            "typedef struct Point {\n"
            "    int x;\n"
            "} Point;\n"
            "\n"
            "int add(int a, int b)\n"
            "{\n"
            "    return a + b;\n"
            "}\n")

    assert c_marks(text) == [
        (1, "Name: FUN_00401000"),
        (2, "struct Point"),
        (6, "int add(int a, int b)"),
    ]


def test_c_a_function_returning_a_struct_is_a_function():
    assert c_marks("struct Point *make_point(void) {\n}\n") == [(1, "struct Point *make_point(void) {")]


def test_c_calls_and_indented_lines_are_not_functions():
    assert c_marks("    helper(1);\nhelper(2);\n") == []


###########################################################
# JSON chunker
###########################################################

def json_marks(text):
    return chunkers.JsonChunker().marks(text.splitlines())


def test_json_marks_top_level_keys_with_their_shapes():
    text = ('{\n'
            '  "obj": {\n'
            '    "inner": 1\n'
            '  },\n'
            '  "arr": [1, 2],\n'
            '  "text": "abc",\n'
            '  "num": 3\n'
            '}\n')

    assert json_marks(text) == [
        (2, "obj (object, 1 keys)"),
        (5, "arr (array, 2 items)"),
        (6, "text (string, 3 chars)"),
        (7, "num (int)"),
    ]


def test_json_nested_keys_do_not_shadow_top_level_keys():
    text = ('{\n'
            '  "a": {\n'
            '    "b": 1\n'
            '  },\n'
            '  "b": 2\n'
            '}\n')

    assert json_marks(text) == [(2, "a (object, 1 keys)"), (5, "b (int)")]


def test_json_nested_keys_on_an_inline_opening_are_skipped():
    text = '{"a": {\n    "inner": 1\n  },\n  "b": 2\n}\n'

    assert json_marks(text) == [(4, "b (int)")]


def test_json_repeated_keys_are_marked_once():
    text = '{\n  "a": 1,\n  "a": 2\n}\n'

    assert json_marks(text) == [(2, "a (int)")]


def test_json_that_does_not_parse_still_marks_keys():
    assert json_marks('{\n  "a": 1,\n  "b":\n') == [(2, "a"), (3, "b")]


def test_json_with_an_array_root_marks_object_keys():
    assert json_marks('[\n  {\n    "a": 1\n  }\n]\n') == [(3, "a")]


###########################################################
# Markdown chunker
###########################################################

def test_markdown_marks_headings_by_depth_outside_fences():
    text = ("# Title\n"
            "text\n"
            "```\n"
            "# not a heading\n"
            "```\n"
            "## Section ##\n")

    marks = chunkers.MarkdownChunker().marks(text.splitlines())

    assert marks == [(1, "Title"), (6, "  Section")]


###########################################################
# Python chunker
###########################################################

def test_python_marks_methods_and_async_functions():
    text = "class Thing:\n    def method(self):\n        pass\nasync  def fetch():\n    pass\n"

    marks = chunkers.PythonChunker().marks(text.splitlines())

    assert marks == [(1, "class Thing"), (2, "  def method"), (4, "async def fetch")]


###########################################################
# Line chunker
###########################################################

def test_lines_are_windowed():
    lines = ["x"] * (chunkers.LineChunker.WINDOW + 10)

    marks = chunkers.LineChunker().marks(lines)

    assert marks == [(1, "lines 1-200"), (201, "lines 201-210")]


###########################################################
# Registration
###########################################################

def test_a_registered_chunker_takes_precedence(monkeypatch):
    monkeypatch.setattr(chunkers, "REGISTERED", list(chunkers.REGISTERED))

    class Custom(chunkers.Chunker):
        name = "custom"
        extensions = (".py",)

    assert chunkers.register_chunker(Custom) is Custom
    assert chunkers.get_chunker("x.py").name == "custom"


def test_registering_twice_does_not_duplicate(monkeypatch):
    monkeypatch.setattr(chunkers, "REGISTERED", list(chunkers.REGISTERED))
    count = len(chunkers.REGISTERED)

    chunkers.register_chunker(chunkers.PythonChunker)

    assert len(chunkers.REGISTERED) == count


def test_the_fallback_is_listed_as_such():
    assert ("lines", "(fallback)") in chunkers.list_chunkers()


###########################################################
# Region lookup
###########################################################

def test_a_partial_region_name_is_resolved(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    return 1\n\ndef beta():\n    return 2\n")

    assert "return 2" in chunkers.slice_region(str(target), "bet")


def test_an_exact_region_name_is_resolved(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    return 1\n\ndef beta():\n    return 2\n")

    region = chunkers.slice_region(str(target), "def_beta")

    assert "return 2" in region
    assert "return 1" not in region


def test_an_ambiguous_region_name_warns(tmp_path, monkeypatch):
    target = tmp_path / "sample.py"
    target.write_text("def alpha():\n    pass\n\ndef beta():\n    pass\n")
    warnings = []
    monkeypatch.setattr(chunkers.logger, "log_warning", warnings.append)

    assert chunkers.slice_region(str(target), "def") == ""
    assert "def_alpha" in warnings[0]
