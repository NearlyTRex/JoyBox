#!/usr/bin/env python3
#
# Runs on the LLM server beside ollama, for what its API does not cover.
#
#   ollama-helper select   write the GPU choice for ollama's next start
#   ollama-helper serve    answer GET /hardware with the server's GPUs and RAM
#
# Only the standard library is used, since this runs on a bare server.

# Imports
import json
import os
import socketserver
import subprocess
import sys
from wsgiref import simple_server

# Where ollama's unit reads the GPU choice from
GPU_ENV_FILE = "/run/ollama/gpus.env"

# Port the hardware report is served on, beside ollama's 11434
HELPER_PORT = 11435

# Address the hardware report is served on
HELPER_HOST = "127.0.0.1"

###########################################################
# GPUs
###########################################################

# Fields read from nvidia-smi, in order
GPU_FIELDS = ["index", "uuid", "name", "pci.bus_id", "memory.total", "memory.free"]

# Parse nvidia-smi's csv rows into GPU entries
def parse_gpus(csv_text):
    gpus = []
    for line in csv_text.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != len(GPU_FIELDS):
            continue
        index, uuid, name, bus_id, total, free = parts
        try:
            gpus.append({
                "index": int(index),
                "uuid": uuid,
                "name": name,
                "bus_id": bus_id,
                "vram_total_mb": int(total),
                "vram_free_mb": int(free),
            })
        except ValueError:
            continue
    return gpus

# Convert nvidia-smi's bus id to the sysfs device name
# nvidia-smi prints an eight digit domain, sysfs a four digit one.
def sysfs_device_name(bus_id):
    return bus_id.lower()[-12:]

# Check whether the firmware drew the console on this card
def is_boot_vga(bus_id, sysfs_root = "/sys/bus/pci/devices"):
    try:
        with open(os.path.join(sysfs_root, sysfs_device_name(bus_id), "boot_vga"), encoding = "utf-8") as handle:
            return handle.read().strip() == "1"
    except OSError:
        return False

# Read the GPUs, marking the display card
def read_gpus(run = subprocess.run, sysfs_root = "/sys/bus/pci/devices"):
    try:
        result = run(
            ["nvidia-smi", "--query-gpu=%s" % ",".join(GPU_FIELDS), "--format=csv,noheader,nounits"],
            capture_output = True, text = True, timeout = 30, check = False)
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    gpus = parse_gpus(result.stdout)
    for gpu in gpus:
        gpu["display"] = is_boot_vga(gpu["bus_id"], sysfs_root)
    return gpus

# Choose the GPUs ollama computes on: every card but the display one, so a
# card added later is used unedited, or the display card when it is the only one
def compute_gpus(gpus):
    chosen = [gpu for gpu in gpus if not gpu.get("display")]
    return chosen or list(gpus)

###########################################################
# Memory
###########################################################

# Parse /proc/meminfo lines into {key: megabytes}, skipping lines without a number
def parse_meminfo(lines):
    values = {}
    for line in lines:
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields and fields[0].isdigit():
            values[key.strip()] = int(fields[0]) // 1024
    return values

# Read total and available RAM from /proc/meminfo, in megabytes
def read_ram(meminfo_file = "/proc/meminfo"):
    try:
        with open(meminfo_file, encoding = "utf-8") as handle:
            values = parse_meminfo(handle)
    except OSError:
        return 0, 0
    return values.get("MemTotal", 0), values.get("MemAvailable", 0)

###########################################################
# Commands
###########################################################

# Build the environment file that points ollama at the chosen GPUs
def build_gpu_env(gpus):
    chosen = compute_gpus(gpus)
    if not chosen:
        return ""
    return "CUDA_VISIBLE_DEVICES=%s\n" % ",".join(gpu["uuid"] for gpu in chosen)

# Write the GPU choice where ollama's unit reads it
def select(gpus, env_file = GPU_ENV_FILE):
    os.makedirs(os.path.dirname(env_file), exist_ok = True)
    with open(env_file, "w", encoding = "utf-8") as handle:
        handle.write(build_gpu_env(gpus))
    return True

# Build the hardware report
def build_report(gpus, ram_total_mb, ram_available_mb):
    chosen = compute_gpus(gpus)
    chosen_uuids = {gpu["uuid"] for gpu in chosen}
    return {
        "gpus": [dict(gpu, compute = gpu["uuid"] in chosen_uuids) for gpu in gpus],
        "compute_vram_total_mb": sum(gpu["vram_total_mb"] for gpu in chosen),
        "compute_vram_free_mb": sum(gpu["vram_free_mb"] for gpu in chosen),
        "compute_gpu_count": len(chosen),
        "ram_total_mb": ram_total_mb,
        "ram_available_mb": ram_available_mb,
    }

# Answer GET /hardware with the report; any other path is 404, any other method 405
def hardware_app(environ, start_response):
    if environ["PATH_INFO"].rstrip("/") != "/hardware":
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not Found\n"]
    if environ["REQUEST_METHOD"] != "GET":
        start_response("405 Method Not Allowed", [("Content-Type", "text/plain"), ("Allow", "GET")])
        return [b"Method Not Allowed\n"]
    body = json.dumps(build_report(read_gpus(), *read_ram())).encode()
    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
    return [body]

# A server that answers each request on its own thread, so a slow nvidia-smi holds no one up
class ThreadingWSGIServer(socketserver.ThreadingMixIn, simple_server.WSGIServer):
    daemon_threads = True

# A request handler that keeps requests out of the log
class QuietHandler(simple_server.WSGIRequestHandler):
    # Drop the access log line the base handler writes to stderr
    def log_message(self, format, *args):
        pass

# Make the server for the hardware report
def make_server(port = HELPER_PORT, host = HELPER_HOST):
    return simple_server.make_server(
        host, port, hardware_app, server_class = ThreadingWSGIServer, handler_class = QuietHandler)

# Serve the hardware report until stopped
# On localhost only, like ollama: clients reach both through an SSH tunnel.
def serve(port = HELPER_PORT, host = HELPER_HOST):
    make_server(port, host).serve_forever()

# Run a command by name
def main(argv):
    if len(argv) == 2 and argv[1] == "select":
        return 0 if select(read_gpus()) else 1
    if len(argv) == 2 and argv[1] == "serve":
        serve()
        return 0
    sys.stderr.write("usage: ollama-helper select|serve\n")
    return 2

# Start
if __name__ == "__main__":
    sys.exit(main(sys.argv))
