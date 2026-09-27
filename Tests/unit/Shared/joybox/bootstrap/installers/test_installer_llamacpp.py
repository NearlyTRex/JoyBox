# Local imports
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Build inputs
#
# llama.cpp's build changes under the installer: a missing package fails the
# configure step, and a flag it no longer reads is silently ignored.
###########################################################

def build(backend):
    llamacpp = installers.LlamaCpp(RecordingConnection())
    llamacpp.backend = backend
    return llamacpp


def test_the_vulkan_backend_has_the_spirv_headers_its_shaders_need(isolated_settings):
    assert "spirv-headers" in build("vulkan").get_build_dependencies()


def test_model_downloads_get_https(isolated_settings):
    # Without OpenSSL headers the build succeeds but cannot fetch models
    for backend in ("cpu", "cuda", "vulkan", "hip"):
        assert "libssl-dev" in build(backend).get_build_dependencies()


def test_only_the_vulkan_backend_pulls_in_vulkan(isolated_settings):
    assert not any("vulkan" in package or package == "spirv-headers"
                   for package in build("cpu").get_build_dependencies())


def test_the_retired_curl_option_is_not_passed(isolated_settings):
    assert not any(flag.startswith("-DLLAMA_CURL") for flag in build("vulkan").get_cmake_flags())
