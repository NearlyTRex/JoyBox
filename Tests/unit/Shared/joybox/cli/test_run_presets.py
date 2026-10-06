# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import run_presets


@pytest.fixture
def tool(monkeypatch, tmp_path, isolated_settings):
    harness = CommandHarness(monkeypatch, run_presets)
    harness.codes = []
    harness.commands = []
    harness.output = str(tmp_path)
    monkeypatch.setattr(run_presets.environment, "get_command_path", lambda name: f"/bin/{name}")

    def fake_run(cmd, verbose = False, pretend_run = False, exit_on_failure = False):
        harness.commands.append(cmd)
        return harness.codes.pop(0) if harness.codes else 0
    monkeypatch.setattr(run_presets.command, "run_returncode_command", fake_run)
    return harness


def test_the_preset_group_is_required(tool, capsys):
    assert tool.exit_code("-o", tool.output) == 2
    assert "--preset_option_group_type" in capsys.readouterr().err


@pytest.mark.parametrize("group", list(config.PresetOptionGroupType))
def test_every_group_builds_backup_commands(tool, group):
    tool.run("-o", tool.output, "-g", group.val())

    options = config.presets_option_groups[group]
    expected_runs = len(options.get("subcategories", [None]))
    assert len(tool.commands) == expected_runs
    for cmd in tool.commands:
        assert cmd[:3] == ["/bin/backup_tool", "-o", tool.output]
        assert ["-u", options["supercategory"]] == cmd[3:5]


def test_a_group_with_subcategories_runs_once_per_platform(tool):
    tool.run("-o", tool.output, "-g", "Backup_SonyPSN")

    options = config.presets_option_groups[config.PresetOptionGroupType.BACKUP_SONYPSN]
    assert [cmd[-1] for cmd in tool.commands] == list(options["subcategories"])
    assert all(cmd[-4:-2] == ["-c", options["category"]] for cmd in tool.commands)


def test_a_group_with_a_whole_category_runs_once(tool):
    tool.run("-o", tool.output, "-g", "Backup_Microsoft")

    options = config.presets_option_groups[config.PresetOptionGroupType.BACKUP_MICROSOFT]
    assert tool.commands == [[
        "/bin/backup_tool", "-o", tool.output,
        "-u", options["supercategory"], "-c", options["category"]]]


def test_a_supercategory_only_group_runs_once(tool, monkeypatch):
    group = config.PresetOptionGroupType.BACKUP_OTHERGEN
    monkeypatch.setitem(config.presets_option_groups, group, {"supercategory": config.Supercategory.ROMS})

    tool.run("-o", tool.output, "-g", group.val())

    assert tool.commands == [["/bin/backup_tool", "-o", tool.output, "-u", config.Supercategory.ROMS]]


def test_a_group_naming_nothing_runs_nothing(tool, monkeypatch):
    group = config.PresetOptionGroupType.BACKUP_OTHERGEN
    monkeypatch.setitem(config.presets_option_groups, group, {})

    tool.run("-o", tool.output, "-g", group.val())

    assert tool.commands == []


def test_pass_through_flags_reach_every_command(tool):
    tool.run("-o", tool.output, "-g", "Backup_Microsoft", "-v", "-x", "-e", "-i")

    cmd = tool.commands[0]
    for flag in ("--verbose", "--exit_on_failure", "--skip_existing", "--skip_identical"):
        assert flag in cmd


def test_a_failed_preset_command_exits_with_an_error(tool):
    tool.codes = [0, 3]

    assert tool.exit_code("-o", tool.output, "-g", "Backup_SonyPSN") == 1
    assert len(tool.commands) == len(
        config.presets_option_groups[config.PresetOptionGroupType.BACKUP_SONYPSN]["subcategories"])


class OtherTool:

    def val(self):
        return "other_tool"

    def __str__(self):
        return self.val()


def test_an_unsupported_tool_exits_with_an_error(tool, monkeypatch, caplog):
    build_parser = run_presets.build_parser

    def parser_with_other_tool():
        parser = build_parser()
        parse_known_args = parser.parse_known_args

        def parse():
            args, unknown = parse_known_args()
            args.preset_tool_type = OtherTool()
            return args, unknown
        parser.parse_known_args = parse
        return parser
    monkeypatch.setattr(run_presets, "build_parser", parser_with_other_tool)

    assert tool.exit_code("-o", tool.output, "-g", "Backup_Microsoft") == 1
    assert "Unsupported preset tool other_tool" in caplog.text
    assert tool.commands == []


def test_run_goes_through_the_shared_error_handling(tool):
    tool.run("-o", tool.output, "-g", "Backup_Microsoft")

    assert len(tool.commands) == 1


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, run_presets)
