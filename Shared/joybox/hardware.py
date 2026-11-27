# Imports
import glob

# Local imports
from joybox import command
from joybox import logger
from joybox import serialization

###########################################################
# GPU detection (NVIDIA)
###########################################################

# Get NVIDIA GPU info via nvidia-smi
def get_nvidia_gpu_info():
    output = command.run_output_command(
        ["nvidia-smi", "--query-gpu=name,memory.total,memory.free,memory.used",
         "--format=csv,noheader,nounits"])
    if not output:
        return []
    gpus = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4:
            try:
                gpus.append({
                    "name": parts[0],
                    "vram_total_mb": int(parts[1]),
                    "vram_free_mb": int(parts[2]),
                    "vram_used_mb": int(parts[3]),
                })
            except ValueError:
                continue
    return gpus

###########################################################
# GPU detection (AMD / Intel Arc, Linux)
###########################################################

# Where the DRM driver exposes each card's dedicated VRAM
DRM_VRAM_TOTAL_GLOB = "/sys/class/drm/card*/device/mem_info_vram_total"

# PCI vendor ids exposed at /sys/class/drm/card*/device/vendor
DRM_VENDOR_NAMES = {
    "0x1002": "AMD GPU",
    "0x8086": "Intel GPU",
    "0x10de": "NVIDIA GPU",
}

# The integer a sysfs file holds, or None when it cannot be read or is not one
def read_sysfs_int(path):
    contents = serialization.read_text_file(path)
    if contents is None:
        return None
    try:
        return int(contents.strip())
    except ValueError:
        return None

# Get dedicated AMD and Intel Arc VRAM from DRM sysfs mem_info_vram_*, one entry per
# card in the NVIDIA shape; integrated GPUs, which have no such file, are skipped
def get_drm_gpu_info():
    gpus = []
    for total_path in sorted(glob.glob(DRM_VRAM_TOTAL_GLOB)):
        total_bytes = read_sysfs_int(total_path)
        if not total_bytes or total_bytes <= 0:
            continue
        used_bytes = read_sysfs_int(total_path.replace("mem_info_vram_total", "mem_info_vram_used")) or 0
        vendor = (serialization.read_text_file(total_path.replace("mem_info_vram_total", "vendor")) or "").strip()
        total_mb = total_bytes // (1024 * 1024)
        used_mb = used_bytes // (1024 * 1024)
        gpus.append({
            "name": DRM_VENDOR_NAMES.get(vendor, "GPU"),
            "vram_total_mb": total_mb,
            "vram_free_mb": max(total_mb - used_mb, 0),
            "vram_used_mb": used_mb,
        })
    return gpus

# Get AMD VRAM from rocm-smi's CSV, by column header, when DRM sysfs has none;
# [] when rocm-smi is missing or its output does not parse
def get_amd_rocm_gpu_info():
    output = command.run_output_command(
        ["rocm-smi", "--showmeminfo", "vram", "--csv"])
    if not output:
        return []
    lines = [line for line in output.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        return []
    header = [col.strip().lower() for col in lines[0].split(",")]
    total_idx = None
    used_idx = None
    for i, col in enumerate(header):
        if "memory" not in col:
            continue
        if "used" in col:
            used_idx = i
        elif "total" in col:
            total_idx = i
    if total_idx is None:
        return []
    gpus = []
    for row in lines[1:]:
        cells = [cell.strip() for cell in row.split(",")]
        if len(cells) <= total_idx:
            continue
        try:
            total_mb = int(cells[total_idx]) // (1024 * 1024)
        except ValueError:
            continue
        used_mb = 0
        if used_idx is not None and len(cells) > used_idx:
            try:
                used_mb = int(cells[used_idx]) // (1024 * 1024)
            except ValueError:
                used_mb = 0
        gpus.append({
            "name": "AMD GPU",
            "vram_total_mb": total_mb,
            "vram_free_mb": max(total_mb - used_mb, 0),
            "vram_used_mb": used_mb,
        })
    return gpus

###########################################################
# GPU dispatch
###########################################################

# Get detected GPUs, richest source first: NVIDIA (nvidia-smi), then AMD / Intel Arc
# (DRM sysfs), then AMD (rocm-smi). Each entry has name and vram_total_mb /
# vram_free_mb / vram_used_mb.
def get_gpu_info():
    gpus = get_nvidia_gpu_info()
    if gpus:
        return gpus
    gpus = get_drm_gpu_info()
    if gpus:
        return gpus
    return get_amd_rocm_gpu_info()

# Get the primary GPU (the card with the most total VRAM), or None if none detected
def get_primary_gpu():
    gpus = get_gpu_info()
    if not gpus:
        return None
    return max(gpus, key = lambda gpu: gpu.get("vram_total_mb", 0))

# Get primary GPU name
def get_gpu_name():
    gpu = get_primary_gpu()
    return gpu["name"] if gpu else None

# Get primary GPU total VRAM in MB
def get_gpu_vram_total_mb():
    gpu = get_primary_gpu()
    return gpu["vram_total_mb"] if gpu else 0

# Get primary GPU free VRAM in MB
def get_gpu_vram_free_mb():
    gpu = get_primary_gpu()
    return gpu["vram_free_mb"] if gpu else 0

###########################################################
# System RAM detection
###########################################################

# Kernel memory statistics
MEMINFO_PATH = "/proc/meminfo"

# Get one /proc/meminfo field in MB, or 0 if it cannot be read
def get_meminfo_mb(field):
    for line in serialization.read_text_lines(MEMINFO_PATH) or []:
        if line.startswith(field + ":"):
            try:
                return int(line.split()[1]) // 1024
            except (ValueError, IndexError):
                return 0
    return 0

# Get total system RAM in MB
def get_system_ram_mb():
    return get_meminfo_mb("MemTotal")

# MemAvailable from /proc/meminfo in megabytes; 0 when it cannot be read
def get_system_ram_available_mb():
    return get_meminfo_mb("MemAvailable")

###########################################################
# Summary
###########################################################

# Get hardware summary dict
def get_hardware_summary():
    gpu = get_primary_gpu()
    return {
        "gpu_name": gpu["name"] if gpu else "None detected",
        "gpu_vram_total_mb": gpu["vram_total_mb"] if gpu else 0,
        "gpu_vram_free_mb": gpu["vram_free_mb"] if gpu else 0,
        "system_ram_mb": get_system_ram_mb(),
        "system_ram_available_mb": get_system_ram_available_mb(),
    }

# Print hardware summary, this machine's unless one is given
def print_hardware_summary(hw = None):
    hw = hw or get_hardware_summary()
    logger.log_info("Hardware Summary:")
    logger.log_info("  GPU: %s" % hw["gpu_name"])
    if hw["gpu_vram_total_mb"] > 0:
        logger.log_info("  VRAM: %d MB total, %d MB free" % (hw["gpu_vram_total_mb"], hw["gpu_vram_free_mb"]))
    logger.log_info("  RAM: %d MB total, %d MB available" % (hw["system_ram_mb"], hw["system_ram_available_mb"]))
