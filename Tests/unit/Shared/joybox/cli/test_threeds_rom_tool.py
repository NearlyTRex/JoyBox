# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import threeds_rom_tool


###########################################################
# Action dispatch
#
# Each action applies only to the file kinds it converts from; the rest of
# the directory is left alone.
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, threeds_rom_tool)
    harness.calls = []
    for name in ("convert_3ds_cia_to_cci", "convert_3ds_cci_to_cia", "trim_3ds_cci", "untrim_3ds_cci", "extract_3ds_cia"):
        monkeypatch.setattr(threeds_rom_tool.nintendo, name,
            lambda name = name, **kwargs: harness.calls.append((name, kwargs["src_3ds_file"].rsplit("/", 1)[-1],
                (kwargs.get("dest_3ds_file") or kwargs["extract_dir"]).rsplit("/", 1)[-1])))
    monkeypatch.setattr(threeds_rom_tool.nintendo, "get_3ds_file_info",
        lambda src_3ds_file, **kwargs: "info:" + src_3ds_file.rsplit("/", 1)[-1])
    for name in ("A.cia", "B.3ds", "C.trim.3ds"):
        (tmp_path / name).write_bytes(b"x")
    return harness


@pytest.mark.parametrize("flag, action, expected", [
    ("-a", "Convert CIA to 3DS(CCI)", [("convert_3ds_cia_to_cci", "A.cia", "A.trim.3ds")]),
    ("-b", "Convert 3DS(CCI) to CIA", [("convert_3ds_cci_to_cia", "B.3ds", "B.cia"), ("convert_3ds_cci_to_cia", "C.trim.3ds", "C.cia")]),
    ("-t", "Trim 3DS(CCI)", [("trim_3ds_cci", "B.3ds", "B.trim.3ds")]),
    ("-u", "Untrim 3DS(CCI)", [("untrim_3ds_cci", "C.trim.3ds", "C.3ds")]),
    ("-e", "Extract CIA", [("extract_3ds_cia", "A.cia", "A")]),
])
def test_each_action_converts_only_its_source_kind(tool, tmp_path, flag, action, expected):
    tool.run("-i", str(tmp_path), flag)

    assert tool.previews == [("3DS ROM tool", ["Path: %s" % tmp_path, "Action: %s" % action])]
    assert sorted(tool.calls) == expected


def test_info_is_printed_for_every_image(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-n", "--no-preview")

    assert sorted(info for info in tool.infos if info.startswith("info:")) == ["info:A.cia", "info:B.3ds", "info:C.trim.3ds"]
    assert tool.calls == []


def test_without_an_action_nothing_is_called(tool, tmp_path):
    tool.run("-i", str(tmp_path), "--no-preview")

    assert tool.calls == []


def test_a_declined_preview_converts_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-a")

    assert tool.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, threeds_rom_tool)
