# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
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


def test_cmake_flags_select_the_backend(isolated_settings):
    expected = {"cpu": None, "cuda": "-DGGML_CUDA=ON", "vulkan": "-DGGML_VULKAN=ON", "hip": "-DGGML_HIP=ON"}
    for backend, flag in expected.items():
        flags = build(backend).get_cmake_flags()
        assert flags[:2] == ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=/usr/local"]
        assert flags[2:] == ([flag] if flag else [])


###########################################################
# Status
###########################################################

SERVER = "/usr/local/bin/llama-server"


def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.LlamaCpp(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    llamacpp, _ = make()
    assert llamacpp.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_installed_binaries(isolated_settings):
    llamacpp, _ = make(existing_paths = [SERVER, "/usr/local/bin/llama-bench"])
    assert llamacpp.is_installed()
    assert llamacpp.get_package_status() == {
        "installed": ["llama-server", "llama-bench"],
        "missing": ["llama-cli"],
    }


###########################################################
# Install
###########################################################

def test_fresh_install_clones_builds_and_installs(isolated_settings):
    llamacpp, connection = make(existing_paths = [SERVER])
    assert llamacpp.install()
    source = llamacpp.source_dir
    assert connection.ran("apt-get install -y", "libvulkan-dev")
    assert os.path.dirname(source) in connection.made_directories
    assert connection.ran("clone --depth 1 https://github.com/ggml-org/llama.cpp.git", source)
    assert connection.ran("-S", source, "-B", f"{source}/build", "-DGGML_VULKAN=ON")
    assert connection.ran("--build", f"{source}/build", "--config Release -j")
    assert connection.ran("--install", f"{source}/build")
    install_calls = [call for call in connection.called("run_blocking") if "--install" in call[1][0]]
    assert [call[2]["sudo"] for call in install_calls] == [True]


def test_existing_checkout_is_fast_forwarded(isolated_settings):
    llamacpp, connection = make()
    connection.existing_paths.update({os.path.join(llamacpp.source_dir, ".git"), SERVER})
    assert llamacpp.install()
    assert connection.ran("pull --ff-only")
    assert not connection.ran("clone")


@pytest.mark.parametrize("fragment", [
    "install -y build-essential",
    "clone --depth",
    " -S ",
    "--build",
    "--install",
])
def test_a_failing_step_stops_the_install(isolated_settings, fragment):
    llamacpp, connection = make(existing_paths = [SERVER], return_codes = {fragment: 1})
    assert not llamacpp.install()
    assert connection.ran(fragment.strip())


def test_install_fails_when_the_server_binary_is_absent(isolated_settings):
    llamacpp, connection = make()
    assert not llamacpp.install()
    assert connection.ran("--install")


###########################################################
# Uninstall
###########################################################

def test_uninstall_removes_only_present_binaries_and_keeps_source(isolated_settings):
    present = [SERVER, "/usr/local/bin/llama-tokenize"]
    llamacpp, connection = make(existing_paths = present)
    assert llamacpp.uninstall()
    assert connection.removed_paths == present
    assert all(call[2]["sudo"] for call in connection.called("remove_file_or_directory"))
