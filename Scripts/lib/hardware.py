# Local imports
import command
import logger

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

# Get primary GPU name
def get_gpu_name():
    gpus = get_nvidia_gpu_info()
    if gpus:
        return gpus[0]["name"]
    return None

# Get primary GPU total VRAM in MB
def get_gpu_vram_total_mb():
    gpus = get_nvidia_gpu_info()
    if gpus:
        return gpus[0]["vram_total_mb"]
    return 0

# Get primary GPU free VRAM in MB
def get_gpu_vram_free_mb():
    gpus = get_nvidia_gpu_info()
    if gpus:
        return gpus[0]["vram_free_mb"]
    return 0

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
    gpus = get_nvidia_gpu_info()
    gpu = gpus[0] if gpus else None
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
