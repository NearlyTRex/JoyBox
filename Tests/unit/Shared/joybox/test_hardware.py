# Imports
import pytest

# Local imports
from joybox import hardware


###########################################################
# Hardware summary
#
# ollama sizes its model recommendations from this, so a zero where a real
# figure belongs silently downgrades every suggestion - and a crash on a
# machine with no GPU would block the tool entirely.
###########################################################

SUMMARY_KEYS = [
    "gpu_name", "gpu_vram_total_mb", "gpu_vram_free_mb",
    "system_ram_mb", "system_ram_available_mb",
]


###########################################################
# Detection without hardware
###########################################################

@pytest.fixture
def no_gpus(monkeypatch):
    monkeypatch.setattr(hardware, "get_nvidia_gpu_info", lambda: [])
    monkeypatch.setattr(hardware, "get_drm_gpu_info", lambda: [])
    monkeypatch.setattr(hardware, "get_amd_rocm_gpu_info", lambda: [])


def test_no_gpu_yields_no_primary(no_gpus):
    assert hardware.get_primary_gpu() is None


def test_no_gpu_reports_zero_vram(no_gpus):
    assert hardware.get_gpu_vram_total_mb() == 0
    assert hardware.get_gpu_vram_free_mb() == 0


def test_no_gpu_reports_no_name(no_gpus):
    assert hardware.get_gpu_name() is None


def test_the_summary_survives_no_gpu(no_gpus):
    summary = hardware.get_hardware_summary()

    assert summary["gpu_name"] == "None detected"
    assert summary["gpu_vram_total_mb"] == 0


###########################################################
# Detection order
###########################################################

def test_nvidia_is_preferred(monkeypatch):
    monkeypatch.setattr(hardware, "get_nvidia_gpu_info", lambda: [{"name": "nvidia"}])
    monkeypatch.setattr(hardware, "get_drm_gpu_info", lambda: [{"name": "drm"}])
    monkeypatch.setattr(hardware, "get_amd_rocm_gpu_info", lambda: [{"name": "rocm"}])

    assert hardware.get_gpu_info() == [{"name": "nvidia"}]


def test_drm_is_the_second_choice(monkeypatch):
    monkeypatch.setattr(hardware, "get_nvidia_gpu_info", lambda: [])
    monkeypatch.setattr(hardware, "get_drm_gpu_info", lambda: [{"name": "drm"}])
    monkeypatch.setattr(hardware, "get_amd_rocm_gpu_info", lambda: [{"name": "rocm"}])

    assert hardware.get_gpu_info() == [{"name": "drm"}]


def test_rocm_is_the_fallback(monkeypatch):
    monkeypatch.setattr(hardware, "get_nvidia_gpu_info", lambda: [])
    monkeypatch.setattr(hardware, "get_drm_gpu_info", lambda: [])
    monkeypatch.setattr(hardware, "get_amd_rocm_gpu_info", lambda: [{"name": "rocm"}])

    assert hardware.get_gpu_info() == [{"name": "rocm"}]


###########################################################
# Primary selection
###########################################################

def test_the_largest_card_is_primary(monkeypatch):
    # Model sizing has to target the card that can actually hold the weights.
    monkeypatch.setattr(hardware, "get_gpu_info", lambda: [
        {"name": "small", "vram_total_mb": 4096, "vram_free_mb": 4000},
        {"name": "large", "vram_total_mb": 24576, "vram_free_mb": 24000},
    ])

    assert hardware.get_primary_gpu()["name"] == "large"


def test_a_single_card_is_primary(monkeypatch):
    monkeypatch.setattr(hardware, "get_gpu_info", lambda: [
        {"name": "only", "vram_total_mb": 8192, "vram_free_mb": 8000},
    ])

    assert hardware.get_primary_gpu()["name"] == "only"


def test_a_card_missing_its_vram_does_not_win(monkeypatch):
    monkeypatch.setattr(hardware, "get_gpu_info", lambda: [
        {"name": "unknown"},
        {"name": "known", "vram_total_mb": 8192, "vram_free_mb": 8000},
    ])

    assert hardware.get_primary_gpu()["name"] == "known"


def test_the_primary_card_supplies_the_accessors(monkeypatch):
    monkeypatch.setattr(hardware, "get_gpu_info", lambda: [
        {"name": "card", "vram_total_mb": 8192, "vram_free_mb": 4096},
    ])

    assert hardware.get_gpu_name() == "card"
    assert hardware.get_gpu_vram_total_mb() == 8192
    assert hardware.get_gpu_vram_free_mb() == 4096


###########################################################
# System memory
###########################################################

def test_total_ram_is_reported():
    # Reported in MB, so anything plausible is far above zero.
    total = hardware.get_system_ram_mb()

    assert isinstance(total, int)
    assert total >= 0


def test_available_ram_does_not_exceed_total():
    total = hardware.get_system_ram_mb()
    available = hardware.get_system_ram_available_mb()

    if total > 0:
        assert available <= total


def test_a_missing_meminfo_reports_zero(monkeypatch):
    def explode(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("builtins.open", explode)

    assert hardware.get_system_ram_mb() == 0
    assert hardware.get_system_ram_available_mb() == 0


###########################################################
# Summary shape
###########################################################

def test_the_summary_carries_every_key():
    summary = hardware.get_hardware_summary()

    assert sorted(summary) == sorted(SUMMARY_KEYS)


def test_the_summary_figures_are_numeric():
    summary = hardware.get_hardware_summary()

    for key in SUMMARY_KEYS:
        if key == "gpu_name":
            continue
        assert isinstance(summary[key], int)


def test_the_summary_never_reports_a_missing_name():
    # ollama prints this directly, so None would read as a crash.
    assert hardware.get_hardware_summary()["gpu_name"] is not None
