# Imports
import os

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
