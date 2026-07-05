# Imports
import glob

# Local imports
import joybox.command as command
import joybox.logger as logger

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

# PCI vendor ids exposed at /sys/class/drm/card*/device/vendor
DRM_VENDOR_NAMES = {
    "0x1002": "AMD GPU",
    "0x8086": "Intel GPU",
    "0x10de": "NVIDIA GPU",
}

# Get dedicated-GPU VRAM (AMD / Intel Arc) from the Linux DRM sysfs interface.
# The amdgpu and i915/xe drivers expose mem_info_vram_total (and mem_info_vram_used)
# for cards with dedicated VRAM; integrated GPUs share system RAM and have no such
# file, so they are skipped. Returns one entry per card, matching the NVIDIA payload
# shape (free = total - used).
def get_drm_gpu_info():
    gpus = []
    for total_path in sorted(glob.glob("/sys/class/drm/card*/device/mem_info_vram_total")):
        try:
            with open(total_path, "r") as handle:
                total_bytes = int(handle.read().strip())
        except (OSError, ValueError):
            continue
        if total_bytes <= 0:
            continue
        used_bytes = 0
        try:
            with open(total_path.replace("mem_info_vram_total", "mem_info_vram_used"), "r") as handle:
                used_bytes = int(handle.read().strip())
        except (OSError, ValueError):
            used_bytes = 0
        vendor = ""
        try:
            with open(total_path.replace("mem_info_vram_total", "vendor"), "r") as handle:
                vendor = handle.read().strip()
        except OSError:
            vendor = ""
        total_mb = total_bytes // (1024 * 1024)
        used_mb = used_bytes // (1024 * 1024)
        gpus.append({
            "name": DRM_VENDOR_NAMES.get(vendor, "GPU"),
            "vram_total_mb": total_mb,
            "vram_free_mb": max(total_mb - used_mb, 0),
            "vram_used_mb": used_mb,
        })
    return gpus

# Get AMD GPU VRAM via rocm-smi as a fallback when DRM sysfs is unavailable. Parses
# the CSV output, locating the VRAM total/used columns by header name (bytes -> MB)
# rather than by fragile positional matching. Returns [] if rocm-smi is missing or
# the output is unparseable.
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
        if "total" in col and "memory" in col:
            total_idx = i
        elif "used" in col and "memory" in col:
            used_idx = i
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

# Get total system RAM in MB
def get_system_ram_mb():
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return kb // 1024
    except (FileNotFoundError, ValueError):
        pass
    return 0

# Get available system RAM in MB
def get_system_ram_available_mb():
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return kb // 1024
    except (FileNotFoundError, ValueError):
        pass
    return 0

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

# Print hardware summary
def print_hardware_summary():
    hw = get_hardware_summary()
    logger.log_info("Hardware Summary:")
    logger.log_info("  GPU: %s" % hw["gpu_name"])
    if hw["gpu_vram_total_mb"] > 0:
        logger.log_info("  VRAM: %d MB total, %d MB free" % (hw["gpu_vram_total_mb"], hw["gpu_vram_free_mb"]))
    logger.log_info("  RAM: %d MB total, %d MB available" % (hw["system_ram_mb"], hw["system_ram_available_mb"]))
