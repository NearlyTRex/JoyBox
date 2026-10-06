# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import boot_vm_image


###########################################################
# Boot and exit status
###########################################################

@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, boot_vm_image)
    harness.boots = []
    harness.result = True

    def boot(**kwargs):
        harness.boots.append(kwargs)
        return harness.result

    monkeypatch.setattr(boot_vm_image.virtualmachine, "boot_vm_image", boot)
    return harness


def test_an_install_boot_passes_every_setting_and_says_what_comes_next(tool):
    tool.run("-n", "llm", "-i", "/images/llm.iso", "-m", "8192", "-c", "2", "-z", "40", "-t", "0",
             "-e", "-l", "/tmp/console.log", "-r")

    assert tool.boots == [{"vm_name": "llm", "iso_file": "/images/llm.iso", "boot_dir": None, "disk_size": 40,
        "memory": 8192, "vcpus": 2, "ssh_port": 0, "headless": True, "serial_file": "/tmp/console.log",
        "reset": True, "verbose": False, "pretend_run": False, "exit_on_failure": False}]
    assert tool.infos[-2:] == ["Boot what it installed with:", "  boot_vm_image -n llm"]


def test_booting_an_installed_disk_prints_no_follow_up(tool):
    tool.run("-n", "llm")

    assert tool.boots[0]["iso_file"] is None
    assert "Boot what it installed with:" not in tool.infos


def test_a_failed_boot_exits_with_an_error(tool):
    tool.result = False

    assert tool.exit_code("-n", "llm", "-i", "/images/llm.iso") != 0
    assert tool.errors == ["Unable to boot the machine"]
    assert "Boot what it installed with:" not in tool.infos


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, boot_vm_image)
