# Local imports
from joybox import ollama


###########################################################
# Shared values for the ollama suite
#
# ollama.py is large enough that its tests are split by area. Anything more
# than one file needs lives here, so a helper cannot drift between files.
###########################################################

def catalog_of(monkeypatch, models):
    monkeypatch.setattr(ollama, "get_model_catalog", lambda purpose = None: models)


def model(name = "model:8b", purpose = None, vram_mb = 5000, **extra):
    entry = {
        "name": name,
        "display": name,
        "purpose": purpose or ollama.PURPOSE_CHAT,
        "params": "8B",
        "vram_mb": vram_mb,
        "description": "A model",
    }
    entry.update(extra)
    return entry


def installed(name = "qwen3:8b"):
    return {
        "name": name,
        "size_gb": 4.7,
        "parameter_size": "8B",
        "quantization": "Q4_K_M",
    }
