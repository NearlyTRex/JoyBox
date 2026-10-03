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
# NVIDIA
###########################################################

def test_nvidia_cards_are_read_from_nvidia_smi(recording_command):
    recording_command.output = "RTX 4090, 24564, 24000, 564\nRTX 3060, 12288, 12000, 288\n"

    assert hardware.get_nvidia_gpu_info() == [
        {"name": "RTX 4090", "vram_total_mb": 24564, "vram_free_mb": 24000, "vram_used_mb": 564},
        {"name": "RTX 3060", "vram_total_mb": 12288, "vram_free_mb": 12000, "vram_used_mb": 288},
    ]
    assert recording_command.only()[0] == "nvidia-smi"


@pytest.mark.parametrize("output", ["", None])
def test_no_nvidia_smi_output_is_no_cards(recording_command, output):
    recording_command.output = output

    assert hardware.get_nvidia_gpu_info() == []


def test_unusable_nvidia_rows_are_skipped(recording_command):
    recording_command.output = "\n".join([
        "short, 1",
        "  ",
        "Tesla, [N/A], [N/A], [N/A]",
        "Good, 8192, 8000, 192",
    ])

    assert [gpu["name"] for gpu in hardware.get_nvidia_gpu_info()] == ["Good"]


###########################################################
# DRM sysfs
###########################################################

MB = 1024 * 1024


def make_card(root, index, total = None, used = None, vendor = None):
    device = root / ("card%d" % index) / "device"
    device.mkdir(parents = True)
    if total is not None:
        (device / "mem_info_vram_total").write_text("%s\n" % total)
    if used is not None:
        (device / "mem_info_vram_used").write_text("%s\n" % used)
    if vendor is not None:
        (device / "vendor").write_text("%s\n" % vendor)


@pytest.fixture
def drm_root(monkeypatch, tmp_path):
    monkeypatch.setattr(
        hardware, "DRM_VRAM_TOTAL_GLOB", str(tmp_path / "card*" / "device" / "mem_info_vram_total"))
    return tmp_path


def test_a_dedicated_card_is_read_from_sysfs(drm_root):
    make_card(drm_root, 0, total = 16384 * MB, used = 1024 * MB, vendor = "0x1002")

    assert hardware.get_drm_gpu_info() == [
        {"name": "AMD GPU", "vram_total_mb": 16384, "vram_free_mb": 15360, "vram_used_mb": 1024}]


def test_an_integrated_card_is_skipped(drm_root):
    make_card(drm_root, 0, vendor = "0x8086")

    assert hardware.get_drm_gpu_info() == []


@pytest.mark.parametrize("total", ["garbage", 0])
def test_an_unusable_vram_total_is_skipped(drm_root, total):
    make_card(drm_root, 0, total = total, used = 0, vendor = "0x1002")

    assert hardware.get_drm_gpu_info() == []


def test_a_card_without_usage_or_vendor_counts_as_empty(drm_root):
    make_card(drm_root, 0, total = 8192 * MB)

    assert hardware.get_drm_gpu_info() == [
        {"name": "GPU", "vram_total_mb": 8192, "vram_free_mb": 8192, "vram_used_mb": 0}]


def test_an_unreadable_usage_counts_as_empty(drm_root):
    make_card(drm_root, 0, total = 8192 * MB, used = "garbage", vendor = "0x8086")

    gpu = hardware.get_drm_gpu_info()[0]
    assert gpu["name"] == "Intel GPU"
    assert gpu["vram_used_mb"] == 0


def test_free_vram_never_goes_negative(drm_root):
    make_card(drm_root, 0, total = 4096 * MB, used = 8192 * MB, vendor = "0x10de")

    assert hardware.get_drm_gpu_info()[0]["vram_free_mb"] == 0


def test_every_dedicated_card_is_listed(drm_root):
    make_card(drm_root, 0, total = 4096 * MB, vendor = "0x1002")
    make_card(drm_root, 1, total = 8192 * MB, vendor = "0x1002")

    assert [gpu["vram_total_mb"] for gpu in hardware.get_drm_gpu_info()] == [4096, 8192]


###########################################################
# rocm-smi
###########################################################

ROCM_HEADER = "device,VRAM Total Memory (B),VRAM Total Used Memory (B)"

ROCM_UNIFIED = "device,VRAM Total Memory (B),VRAM Total Used Memory (B),GTT Memory (B)"


def test_amd_cards_are_read_from_rocm_smi(recording_command):
    # The used column also says "Total", so it must not be taken for the total.
    recording_command.output = "\n".join([
        ROCM_HEADER,
        "card0,%d,%d" % (16384 * MB, 1024 * MB),
    ])

    assert hardware.get_amd_rocm_gpu_info() == [
        {"name": "AMD GPU", "vram_total_mb": 16384, "vram_free_mb": 15360, "vram_used_mb": 1024}]
    assert recording_command.only()[0] == "rocm-smi"


@pytest.mark.parametrize("output", [None, "", ROCM_HEADER, "device,name\ncard0,radeon"])
def test_unusable_rocm_output_is_no_cards(recording_command, output):
    recording_command.output = output

    assert hardware.get_amd_rocm_gpu_info() == []


def test_unusable_rocm_rows_are_skipped(recording_command):
    recording_command.output = "\n".join([
        ROCM_HEADER,
        "card0",
        "card1,garbage,0",
        "card2,%d,garbage" % (8192 * MB),
        "card3,%d" % (4096 * MB),
    ])

    assert hardware.get_amd_rocm_gpu_info() == [
        {"name": "AMD GPU", "vram_total_mb": 8192, "vram_free_mb": 8192, "vram_used_mb": 0},
        {"name": "AMD GPU", "vram_total_mb": 4096, "vram_free_mb": 4096, "vram_used_mb": 0},
    ]


def test_other_rocm_memory_columns_are_ignored(recording_command):
    recording_command.output = "%s\ncard0,%d,%d,%d" % (ROCM_UNIFIED, 8192 * MB, 2048 * MB, 512 * MB)

    assert hardware.get_amd_rocm_gpu_info()[0]["vram_used_mb"] == 2048


def test_a_rocm_total_without_a_used_column_counts_as_empty(recording_command):
    recording_command.output = "device,VRAM Total Memory (B)\ncard0,%d" % (2048 * MB)

    assert hardware.get_amd_rocm_gpu_info()[0]["vram_free_mb"] == 2048


###########################################################
# System memory
###########################################################

MEMINFO = """MemTotal:       32768000 kB
MemFree:         1024000 kB
MemAvailable:   16384000 kB
"""


@pytest.fixture
def meminfo(monkeypatch, tmp_path):
    path = tmp_path / "meminfo"
    monkeypatch.setattr(hardware, "MEMINFO_PATH", str(path))
    return path


def test_total_ram_is_reported_in_mb(meminfo):
    meminfo.write_text(MEMINFO)

    assert hardware.get_system_ram_mb() == 32000


def test_available_ram_is_reported_in_mb(meminfo):
    meminfo.write_text(MEMINFO)

    assert hardware.get_system_ram_available_mb() == 16000


def test_a_missing_meminfo_reports_zero(meminfo):
    assert hardware.get_system_ram_mb() == 0
    assert hardware.get_system_ram_available_mb() == 0


@pytest.mark.parametrize("contents", ["MemTotal: lots kB\n", "MemTotal:\n", "MemFree: 1 kB\n"])
def test_an_unusable_meminfo_reports_zero(meminfo, contents):
    meminfo.write_text(contents)

    assert hardware.get_system_ram_mb() == 0


###########################################################
# Summary shape
###########################################################

@pytest.fixture
def one_card(monkeypatch, meminfo):
    meminfo.write_text(MEMINFO)
    monkeypatch.setattr(hardware, "get_gpu_info", lambda: [
        {"name": "card", "vram_total_mb": 8192, "vram_free_mb": 4096, "vram_used_mb": 4096}])


def test_the_summary_carries_every_key(one_card):
    summary = hardware.get_hardware_summary()

    assert sorted(summary) == sorted(SUMMARY_KEYS)


def test_the_summary_reports_the_primary_card_and_memory(one_card):
    assert hardware.get_hardware_summary() == {
        "gpu_name": "card",
        "gpu_vram_total_mb": 8192,
        "gpu_vram_free_mb": 4096,
        "system_ram_mb": 32000,
        "system_ram_available_mb": 16000,
    }


def test_the_printed_summary_includes_vram(monkeypatch, one_card):
    lines = []
    monkeypatch.setattr(hardware.logger, "log_info", lines.append)
    hardware.print_hardware_summary()

    assert "  GPU: card" in lines
    assert "  VRAM: 8192 MB total, 4096 MB free" in lines
    assert "  RAM: 32000 MB total, 16000 MB available" in lines


def test_the_printed_summary_omits_vram_without_a_card(monkeypatch, no_gpus, meminfo):
    lines = []
    monkeypatch.setattr(hardware.logger, "log_info", lines.append)
    hardware.print_hardware_summary()

    assert "  GPU: None detected" in lines
    assert not [line for line in lines if "VRAM" in line]
