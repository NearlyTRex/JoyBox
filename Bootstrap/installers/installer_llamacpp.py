# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# llama.cpp
#
# Built from source rather than pulled as a binary, because the useful
# build flags are hardware-specific. Unlike ollama it exposes grammar-
# constrained sampling, fixed seeds, prompt caching and logprobs -- all of
# which promptc needs: grammars for output contracts, seeds for
# reproducible pass@k, and the tokenizer endpoint for exact token budgets.
#
# Backend selection:
#   cpu     portable, always builds
#   cuda    NVIDIA
#   vulkan  AMD/Intel via the ordinary graphics driver, no ROCm required
#   hip     AMD via ROCm
class LlamaCpp(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.source_dir = os.path.expanduser("~/Tools/llama.cpp")
        self.install_prefix = "/usr/local"
        self.server_binary_path = "/usr/local/bin/llama-server"
        self.repository_url = "https://github.com/ggml-org/llama.cpp.git"
        self.backend = "vulkan"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.server_binary_path)

    def get_package_status(self):
        installed = []
        missing = []
        for name in ("llama-server", "llama-cli", "llama-bench"):
            path = os.path.join(self.install_prefix, "bin", name)
            if self.connection.does_file_or_directory_exist(path):
                installed.append(name)
            else:
                missing.append(name)
        return {"installed": installed, "missing": missing}

    def get_build_dependencies(self):
        packages = ["build-essential", "cmake", "git", "libcurl4-openssl-dev"]
        if self.backend == "vulkan":
            packages += ["libvulkan-dev", "glslc", "vulkan-tools"]
        return packages

    def get_cmake_flags(self):
        flags = ["-DCMAKE_BUILD_TYPE=Release",
                 f"-DCMAKE_INSTALL_PREFIX={self.install_prefix}",
                 "-DLLAMA_CURL=ON"]
        if self.backend == "cuda":
            flags.append("-DGGML_CUDA=ON")
        elif self.backend == "vulkan":
            flags.append("-DGGML_VULKAN=ON")
        elif self.backend == "hip":
            flags.append("-DGGML_HIP=ON")
        return flags

    def install(self):

        # Start install
        logger.log_info(f"Installing llama.cpp (backend: {self.backend})")

        # Build dependencies
        logger.log_info("Installing build dependencies")
        code = self.connection.run_blocking(
            ["apt-get", "install", "-y"] + self.get_build_dependencies(), sudo = True)
        if code != 0:
            logger.log_error("Failed to install build dependencies")
            return False

        # Fetch or update the source tree
        if self.connection.does_file_or_directory_exist(os.path.join(self.source_dir, ".git")):
            logger.log_info("Updating existing llama.cpp checkout")
            code = self.connection.run_blocking(["git", "-C", self.source_dir, "pull", "--ff-only"])
        else:
            logger.log_info(f"Cloning llama.cpp into {self.source_dir}")
            self.connection.make_directory(os.path.dirname(self.source_dir))
            code = self.connection.run_blocking(
                ["git", "clone", "--depth", "1", self.repository_url, self.source_dir])
        if code != 0:
            logger.log_error("Failed to fetch llama.cpp source")
            return False

        # Configure
        build_dir = os.path.join(self.source_dir, "build")
        logger.log_info("Configuring build")
        code = self.connection.run_blocking(
            ["cmake", "-S", self.source_dir, "-B", build_dir] + self.get_cmake_flags())
        if code != 0:
            logger.log_error("CMake configuration failed")
            return False

        # Build
        logger.log_info("Building (this takes a while)")
        code = self.connection.run_blocking(
            ["cmake", "--build", build_dir, "--config", "Release", "-j"])
        if code != 0:
            logger.log_error("Build failed")
            return False

        # Install
        logger.log_info("Installing binaries")
        code = self.connection.run_blocking(
            ["cmake", "--install", build_dir], sudo = True)
        if code != 0:
            logger.log_error("Install step failed")
            return False

        # Verify installation
        logger.log_info("Verifying installation")
        if not self.is_installed():
            logger.log_error("llama.cpp installation verification failed")
            return False

        # All done
        logger.log_info("llama.cpp installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling llama.cpp")

        # Remove installed binaries
        for name in ("llama-server", "llama-cli", "llama-bench",
                     "llama-quantize", "llama-perplexity", "llama-tokenize"):
            path = os.path.join(self.install_prefix, "bin", name)
            if self.connection.does_file_or_directory_exist(path):
                self.connection.remove_file_or_directory(path, sudo = True)

        # Leave the source checkout in place; it holds build caches and any
        # local changes, and removing it is not what uninstall implies.
        logger.log_info(f"Source tree left at {self.source_dir}")

        # All done
        logger.log_info("llama.cpp uninstalled")
        return True
