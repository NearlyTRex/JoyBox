# Third-party imports
import pytest

# Local imports
from joybox import ollama
from ollama_helpers import catalog_of, model



###########################################################
# Hardware fit
###########################################################


def test_a_model_that_fits_vram_runs_on_the_gpu(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 4000)])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert found[0]["fit"] == ollama.FIT_GPU
    assert found[0]["fits_vram"] is True


def test_a_model_larger_than_vram_offloads_to_ram(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 12000)])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert found[0]["fit"] == ollama.FIT_OFFLOAD
    assert found[0]["fits_vram"] is False


def test_a_model_larger_than_the_machine_is_left_out(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 64000)])

    assert ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000) == []


def test_an_oversized_model_can_be_asked_for(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 64000)])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000, include_unfit = True)

    assert found[0]["fit"] == ollama.FIT_NONE


def test_a_cloud_model_is_left_out_of_local_recommendations(monkeypatch):
    catalog_of(monkeypatch, [model(cloud_only = True, vram_mb = 0)])

    assert ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000) == []


def test_asking_for_cloud_models_includes_them(monkeypatch):
    catalog_of(monkeypatch, [model(purpose = ollama.PURPOSE_CLOUD, cloud_only = True, vram_mb = 0)])

    found = ollama.get_recommended_models(
        purpose = ollama.PURPOSE_CLOUD, vram_mb = 8000, ram_mb = 32000)

    assert found[0]["fit"] == ollama.FIT_CLOUD


def test_a_model_of_unknown_size_does_not_fit(monkeypatch):
    # An unknown size cannot be promised to load, so it is not recommended.
    catalog_of(monkeypatch, [model(vram_mb = 0)])

    assert ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000) == []


def test_recommendations_are_ordered_by_how_well_they_run(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "offload:14b", vram_mb = 12000),
        model(name = "gpu:8b", vram_mb = 4000),
    ])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert [entry["name"] for entry in found] == ["gpu:8b", "offload:14b"]


def test_another_purpose_is_filtered_out(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "chat:8b", purpose = ollama.PURPOSE_CHAT),
        model(name = "tools:8b", purpose = ollama.PURPOSE_TOOLS),
    ])

    found = ollama.get_recommended_models(
        purpose = ollama.PURPOSE_TOOLS, vram_mb = 8000, ram_mb = 32000)

    assert [entry["name"] for entry in found] == ["tools:8b"]


def test_the_catalog_is_left_unmodified(monkeypatch):
    # The fit depends on the machine asking, so it cannot be written into a
    # catalog that is cached and reused.
    entry = model()
    catalog_of(monkeypatch, [entry])

    ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert "fit" not in entry


###########################################################
# Picking a model
###########################################################

def test_the_largest_model_that_fits_the_gpu_wins(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "small:8b", vram_mb = 4000, params = "8B"),
        model(name = "large:14b", vram_mb = 7000, params = "14B"),
    ])

    best = ollama.get_best_model(purpose = None, vram_mb = 8000, ram_mb = 32000)

    assert best["name"] == "large:14b"


def test_a_gpu_model_beats_a_larger_offloaded_one(monkeypatch):
    # Offloading to system RAM is far slower than a smaller model on the GPU.
    catalog_of(monkeypatch, [
        model(name = "offload:32b", vram_mb = 20000, params = "32B"),
        model(name = "gpu:8b", vram_mb = 4000, params = "8B"),
    ])

    best = ollama.get_best_model(purpose = None, vram_mb = 8000, ram_mb = 32000)

    assert best["name"] == "gpu:8b"


def test_the_largest_offloaded_model_is_taken_when_nothing_fits_the_gpu(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "mid:14b", vram_mb = 12000, params = "14B"),
        model(name = "big:32b", vram_mb = 20000, params = "32B"),
    ])

    best = ollama.get_best_model(purpose = None, vram_mb = 2000, ram_mb = 32000)

    assert best["name"] == "big:32b"


def test_nothing_is_picked_when_nothing_runs(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 64000)])

    assert ollama.get_best_model(purpose = None, vram_mb = 4000, ram_mb = 8000) is None


###########################################################
# Display
###########################################################

def test_a_fitting_model_is_marked_as_such():
    line = ollama.format_model_display(model(vram_mb = 5000, fits_vram = True))

    assert line.startswith("[+]")


def test_a_model_that_does_not_fit_is_marked_differently():
    line = ollama.format_model_display(model(vram_mb = 64000, fits_vram = False))

    assert line.startswith("[-]")


def test_a_display_line_reports_the_size_in_gigabytes():
    line = ollama.format_model_display(model(vram_mb = 5120, fits_vram = True))

    assert "5.0 GB" in line


def test_an_installed_model_is_described_by_its_build():
    line = ollama.format_installed_model_display({
        "name": "qwen3:8b",
        "size_gb": 4.7,
        "parameter_size": "8B",
        "quantization": "Q4_K_M",
    })

    assert line == "qwen3:8b (4.7 GB, 8B Q4_K_M)"


@pytest.mark.parametrize("vram_mb,ram_mb,marker", [
    (8000, 32000, "+"),
    (2000, 32000, "~"),
    (2000, 3000, "-"),
])
def test_a_quantization_is_marked_by_where_it_would_run(vram_mb, ram_mb, marker):
    option = {
        "full_name": "qwen3:8b-q4_K_M",
        "size_mb": 4700,
        "size_str": "4.7GB",
        "context": "128K",
    }

    line = ollama.format_quantization_display(option, vram_mb, ram_mb)

    assert line.startswith("[%s]" % marker)
    assert "qwen3:8b-q4_K_M" in line
    assert "128K context" in line
