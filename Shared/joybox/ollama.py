# Imports
import urllib.parse

# Local imports
from joybox import command
from joybox import commandbase
from joybox import hardware
from joybox import logger
from joybox import network
from joybox import settings
from joybox import runtime

###########################################################
# Ollama API
###########################################################

# Default Ollama API base URL (used when the setting is unset)
OLLAMA_API_BASE_DEFAULT = "http://localhost:11434"

# Get the configured Ollama API base URL (falls back to the local default)
def get_api_base():
    return settings.get_value("Tools.Ollama", "ollama_api_base", OLLAMA_API_BASE_DEFAULT, throw_exception = False)

# Check if Ollama is running
def is_running():
    return network.is_url_reachable(get_api_base())

# Get the SSH destination of the server, when it is reached through a tunnel
# The server's API then listens on its own localhost, and the base URL is the
# local end of the tunnel (the bootstrap's ollama_tunnel component).
def get_ssh_host():
    return settings.get_value("Tools.Ollama", "ollama_ssh_host", "", throw_exception = False) or ""

# Check if the server is reached through an SSH tunnel
def is_tunneled():
    return bool(get_ssh_host())

# Check if the configured server is this machine
# A tunnel's local end is on localhost too, but the server is not.
def is_local_server():
    if is_tunneled():
        return False
    host = urllib.parse.urlparse(get_api_base()).hostname or ""
    return host in ("localhost", "::1", "0.0.0.0") or host.startswith("127.")

# Options for the ollama command, aimed at the configured server
# The command ignores the setting and reads OLLAMA_HOST instead.
def create_client_options():
    options = commandbase.create_command_options()
    options.set_env_var("OLLAMA_HOST", get_api_base())
    return options

# Read a size in megabytes from the settings, or None when unset
def get_setting_mb(field):
    value = str(settings.get_value("Tools.Ollama", field, "", throw_exception = False) or "").strip()
    if not value:
        return None
    if not value.isdigit():
        logger.log_warning("Ignoring [Tools.Ollama] %s, which is not a whole number of megabytes: %s" % (field, value))
        return None
    return int(value)

# Port the helper beside the server reports its hardware on
HELPER_PORT = 11435

# Read the hardware report from the helper beside the server, or None
# ollama's API says nothing about GPUs, so the LLM server image runs a helper
# that does; any other server simply has none.
def read_helper_report():
    host = urllib.parse.urlparse(get_api_base()).hostname
    if not host:
        return None
    if ":" in host:
        host = "[%s]" % host
    report = network.get_remote_json("http://%s:%d/hardware" % (host, HELPER_PORT))
    if not isinstance(report, dict) or "compute_vram_total_mb" not in report:
        return None
    return report

# Get the hardware the configured server runs models on
# Sizes set in the settings win, then the server's helper report, then this
# machine, which is only right when the server is local.
def get_server_hardware():
    hw = dict(hardware.get_hardware_summary(), gpu_count = 1)
    report = read_helper_report()
    if report:
        names = [gpu.get("name", "?") for gpu in report.get("gpus", []) if gpu.get("compute")]
        hw.update(
            gpu_name = ", ".join(names) or "None detected",
            gpu_vram_total_mb = report["compute_vram_total_mb"],
            gpu_vram_free_mb = report.get("compute_vram_free_mb", 0),
            gpu_count = max(report.get("compute_gpu_count", 1), 1),
            system_ram_mb = report.get("ram_total_mb", 0),
            system_ram_available_mb = report.get("ram_available_mb", 0))
    vram_mb = get_setting_mb("ollama_gpu_vram_mb")
    ram_mb = get_setting_mb("ollama_system_ram_mb")
    if vram_mb is not None:
        hw.update(gpu_name = "Configured for %s" % get_api_base(),
            gpu_vram_total_mb = vram_mb, gpu_vram_free_mb = vram_mb)
    elif not report and not is_local_server():
        logger.log_warning(
            "Fits are judged against this machine, not the server at %s, which has no "
            "hardware helper; set [Tools.Ollama] ollama_gpu_vram_mb to the server's VRAM" % get_api_base())
    if ram_mb is not None:
        hw.update(system_ram_mb = ram_mb, system_ram_available_mb = ram_mb)
    return hw

# Start Ollama serve in the background
# A server on another machine cannot be started from here.
def start_serve():
    if is_running():
        return True
    if not is_local_server():
        logger.log_error("Ollama server at %s is not answering" % get_api_base())
        if is_tunneled():
            logger.log_info("It is reached through an SSH tunnel to %s; check it with: systemctl --user status ollama-tunnel" % get_ssh_host())
        return False
    logger.log_info("Starting Ollama server...")
    options = commandbase.create_command_options()
    options.set_is_daemon(True)
    command.run_returncode_command(["ollama", "serve"], options = options)
    for _ in range(10):
        runtime.sleep_program(1)
        if is_running():
            logger.log_info("Ollama server started")
            return True
    logger.log_error("Ollama server failed to start")
    return False

# Ensure Ollama is running, starting it if needed
def ensure_running():
    if is_running():
        return True
    return start_serve()

# List installed models
def list_installed_models():
    result = network.get_remote_json(get_api_base() + "/api/tags")
    if not result or "models" not in result:
        return []
    models = []
    for m in result["models"]:
        details = m.get("details", {})
        models.append({
            "name": m.get("name", ""),
            "size_bytes": m.get("size", 0),
            "size_gb": round(m.get("size", 0) / (1024 ** 3), 1),
            "family": details.get("family", ""),
            "parameter_size": details.get("parameter_size", ""),
            "quantization": details.get("quantization_level", ""),
            "format": details.get("format", ""),
        })
    return sorted(models, key = lambda x: x["name"])

# Pull (download) a model. Runs in passthrough mode so ollama's native progress
# bar streams live to the terminal during multi-GB downloads.
def pull_model(model_name):
    options = create_client_options()
    options.set_passthrough(True)
    code = command.run_returncode_command(
        ["ollama", "pull", model_name],
        options = options)
    return code == 0

# Delete a model
def delete_model(model_name):
    code = command.run_returncode_command(
        ["ollama", "rm", model_name],
        options = create_client_options())
    return code == 0

# Show model info
def show_model(model_name):
    output = command.run_output_command(
        ["ollama", "show", model_name],
        options = create_client_options())
    if output:
        return output
    return None
