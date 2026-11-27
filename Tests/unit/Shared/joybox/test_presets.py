# Third-party imports
import pytest

# Local imports
from joybox import command
from joybox import config
from joybox import environment
from joybox import presets


###########################################################
# Preset commands
#
# A preset option group names platforms; each becomes one backup_tool run
# with the shared flags passed through.
###########################################################

@pytest.fixture
def runs(monkeypatch):
    calls = []
    monkeypatch.setattr(environment, "get_command_path", lambda name: f"/bin/{name}")

    def run_returncode_command(cmd, verbose = False, pretend_run = False, exit_on_failure = False):
        calls.append(cmd)
        return 0
    monkeypatch.setattr(command, "run_returncode_command", run_returncode_command)
    return calls


def test_the_base_command_carries_the_verbose_and_failure_flags(runs):
    base_cmd = presets.get_preset_base_command(config.PresetToolType.BACKUP_TOOL, verbose = True, exit_on_failure = True)

    assert base_cmd == ["/bin/backup_tool", "--verbose", "--exit_on_failure"]


def test_subcategories_expand_to_one_command_each():
    options = {"supercategory": "Roms", "category": "Sony", "subcategories": ["PSN", "PSV"]}

    cmds = presets.get_backup_tool_preset_commands(["tool"], options, "/out", skip_identical = True)

    assert cmds == [
        ["tool", "-o", "/out", "--skip_identical", "-u", "Roms", "-c", "Sony", "-s", "PSN"],
        ["tool", "-o", "/out", "--skip_identical", "-u", "Roms", "-c", "Sony", "-s", "PSV"]]


def test_subcategories_without_a_category_run_the_supercategory_once():
    options = {"supercategory": "Roms", "subcategories": ["PSN"]}

    assert presets.get_backup_tool_preset_commands(["tool"], options, "/out", skip_existing = True) == [
        ["tool", "-o", "/out", "--skip_existing", "-u", "Roms"]]


def test_a_group_without_a_supercategory_runs_nothing():
    assert presets.get_backup_tool_preset_commands(["tool"], {"category": "Sony"}, "/out") == []


def test_a_failed_command_fails_the_run_but_the_rest_still_run(monkeypatch):
    codes = [2, 0]
    ran = []

    def run_returncode_command(cmd, verbose = False, pretend_run = False, exit_on_failure = False):
        ran.append(cmd)
        return codes.pop(0)
    monkeypatch.setattr(command, "run_returncode_command", run_returncode_command)

    assert presets.run_preset_commands([["a"], ["b"]]) is False
    assert ran == [["a"], ["b"]]


def test_a_backup_group_runs_through_backup_tool(runs):
    group = config.PresetOptionGroupType.BACKUP_MICROSOFT

    assert presets.run_presets(config.PresetToolType.BACKUP_TOOL, group, "/out") is True
    assert runs == [["/bin/backup_tool", "-o", "/out", "-u", config.Supercategory.ROMS, "-c", config.Category.MICROSOFT]]
