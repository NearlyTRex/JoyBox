# Imports
import importlib.util
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request

# Third-party imports
import pytest


###########################################################
# ollama-helper
#
# The script the LLM server image runs beside ollama. It is kept in the tree
# as a module so it can be loaded and tested here.
###########################################################

@pytest.fixture(scope = "module")
def helper(repo_root):
    path = os.path.join(repo_root, "Scripts", "autoinstall", "ollama_helper.py")
    spec = importlib.util.spec_from_file_location("ollama_helper", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gpu(uuid, display = False, total = 32768, free = 32000, name = "Card"):
    return {"uuid": uuid, "name": name, "display": display,
        "vram_total_mb": total, "vram_free_mb": free}


SMI_OUTPUT = (
    "0, GPU-aaa, NVIDIA GeForce GTX 1650, 00000000:01:00.0, 4096, 1039\n"
    "1, GPU-bbb, Tesla PG500-216, 00000000:03:00.0, 32768, 7469\n")


###########################################################
# Reading the GPUs
###########################################################

def test_gpus_are_read_from_the_csv(helper):
    gpus = helper.parse_gpus(SMI_OUTPUT)

    assert [g["uuid"] for g in gpus] == ["GPU-aaa", "GPU-bbb"]
    assert gpus[1] == {"index": 1, "uuid": "GPU-bbb", "name": "Tesla PG500-216",
        "bus_id": "00000000:03:00.0", "vram_total_mb": 32768, "vram_free_mb": 7469}


@pytest.mark.parametrize("line", ["", "too, few, fields", "x, GPU-a, Card, 0:1:0.0, lots, 1"])
def test_unreadable_rows_are_skipped(helper, line):
    assert helper.parse_gpus(line) == []


def test_the_bus_id_is_shortened_to_the_sysfs_name(helper):
    assert helper.sysfs_device_name("00000000:03:00.0") == "0000:03:00.0"
    assert helper.sysfs_device_name("00000000:0A:00.0") == "0000:0a:00.0"


@pytest.fixture
def sysfs(tmp_path):
    def device(name, boot_vga):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "boot_vga").write_text("%d\n" % boot_vga)
    device("0000:01:00.0", 1)
    device("0000:03:00.0", 0)
    return str(tmp_path)


def test_the_card_the_firmware_drew_on_is_the_display(helper, sysfs):
    assert helper.is_boot_vga("00000000:01:00.0", sysfs) is True
    assert helper.is_boot_vga("00000000:03:00.0", sysfs) is False
    assert helper.is_boot_vga("00000000:09:00.0", sysfs) is False


def test_read_gpus_marks_the_display_card(helper, sysfs):
    def run(cmd, **kwargs):
        assert cmd[0] == "nvidia-smi"
        return subprocess.CompletedProcess(cmd, 0, stdout = SMI_OUTPUT)

    gpus = helper.read_gpus(run = run, sysfs_root = sysfs)

    assert [(g["uuid"], g["display"]) for g in gpus] == [("GPU-aaa", True), ("GPU-bbb", False)]


def test_no_driver_is_no_gpus(helper):
    def missing(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    def failing(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 9, stdout = "")

    assert helper.read_gpus(run = missing) == []
    assert helper.read_gpus(run = failing) == []


###########################################################
# Choosing the GPUs
###########################################################

def test_every_card_but_the_display_computes(helper):
    gpus = [gpu("GPU-aaa", display = True), gpu("GPU-bbb"), gpu("GPU-ccc")]

    assert [g["uuid"] for g in helper.compute_gpus(gpus)] == ["GPU-bbb", "GPU-ccc"]


def test_a_lone_display_card_still_computes(helper):
    assert [g["uuid"] for g in helper.compute_gpus([gpu("GPU-aaa", display = True)])] == ["GPU-aaa"]


def test_the_chosen_cards_are_named_by_uuid(helper):
    gpus = [gpu("GPU-aaa", display = True), gpu("GPU-bbb"), gpu("GPU-ccc")]

    assert helper.build_gpu_env(gpus) == "CUDA_VISIBLE_DEVICES=GPU-bbb,GPU-ccc\n"


def test_no_gpus_leaves_ollama_to_itself(helper):
    assert helper.build_gpu_env([]) == ""


def test_the_choice_is_written_where_the_unit_reads_it(helper, tmp_path):
    env_file = tmp_path / "run" / "ollama" / "gpus.env"

    assert helper.select([gpu("GPU-aaa", display = True), gpu("GPU-bbb")], str(env_file)) is True
    assert env_file.read_text() == "CUDA_VISIBLE_DEVICES=GPU-bbb\n"


###########################################################
# Reporting
###########################################################

def test_ram_is_read_in_megabytes(helper, tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       31729664 kB\nMemFree: 100 kB\nMemAvailable:   30594048 kB\n")

    assert helper.read_ram(str(meminfo)) == (30986, 29877)


def test_unreadable_ram_is_none(helper, tmp_path):
    assert helper.read_ram(str(tmp_path / "absent")) == (0, 0)


def test_the_report_counts_only_the_computing_cards(helper):
    gpus = [gpu("GPU-aaa", display = True, total = 4096, free = 1000),
        gpu("GPU-bbb", total = 32768, free = 30000),
        gpu("GPU-ccc", total = 32768, free = 20000)]

    report = helper.build_report(gpus, 30986, 29877)

    assert report["compute_vram_total_mb"] == 65536
    assert report["compute_vram_free_mb"] == 50000
    assert report["compute_gpu_count"] == 2
    assert [g["compute"] for g in report["gpus"]] == [False, True, True]
    assert report["ram_total_mb"] == 30986
    assert report["ram_available_mb"] == 29877


@pytest.fixture
def served(helper, monkeypatch):
    monkeypatch.setattr(helper, "read_gpus", lambda: [gpu("GPU-bbb")])
    monkeypatch.setattr(helper, "read_ram", lambda: (1000, 500))
    server = helper.http.server.ThreadingHTTPServer(("127.0.0.1", 0), helper.HardwareHandler)
    thread = threading.Thread(target = server.serve_forever, daemon = True)
    thread.start()
    yield "http://127.0.0.1:%d" % server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.mark.allow_network
def test_the_report_is_served_as_json(served):
    with urllib.request.urlopen(served + "/hardware", timeout = 5) as response:
        report = json.loads(response.read().decode())

    assert report["compute_vram_total_mb"] == 32768
    assert report["ram_total_mb"] == 1000


@pytest.mark.allow_network
def test_other_paths_are_not_found(served):
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(served + "/other", timeout = 5)

    assert raised.value.code == 404


###########################################################
# Commands
###########################################################

def test_select_writes_the_choice(helper, monkeypatch):
    chosen = []
    monkeypatch.setattr(helper, "read_gpus", lambda: ["read"])
    monkeypatch.setattr(helper, "select", lambda gpus: chosen.append(gpus) or True)

    assert helper.main(["ollama-helper", "select"]) == 0
    assert chosen == [["read"]]


def test_serve_starts_the_server(helper, monkeypatch):
    started = []
    monkeypatch.setattr(helper, "serve", lambda: started.append(True))

    assert helper.main(["ollama-helper", "serve"]) == 0
    assert started == [True]


@pytest.mark.parametrize("argv", [["ollama-helper"], ["ollama-helper", "other"]])
def test_anything_else_prints_the_usage(helper, argv, capsys):
    assert helper.main(argv) == 2
    assert "usage" in capsys.readouterr().err
