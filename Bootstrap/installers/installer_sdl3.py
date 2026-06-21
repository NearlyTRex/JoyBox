# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# SDL3
# Built from source because SDL3 (and SDL3_ttf) are not yet available in the
# official Ubuntu/Mint apt repositories. Required by emulators that have ported
# off SDL2, e.g. PPSSPP (master), which calls find_package(SDL3 REQUIRED) and
# find_package(SDL3_ttf REQUIRED). Installs to /usr/local so CMake's
# find_package picks it up automatically.
class Sdl3(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

        # SDL3 core library
        self.sdl_repo = "https://github.com/libsdl-org/SDL"
        self.sdl_tag = "release-3.4.10"
        self.sdl_src = "/tmp/sdl3_src"
        self.sdl_build = "/tmp/sdl3_src/build"

        # SDL3_ttf (text rendering, system freetype, no vendored deps)
        self.sdl_ttf_repo = "https://github.com/libsdl-org/SDL_ttf"
        self.sdl_ttf_tag = "release-3.2.2"
        self.sdl_ttf_src = "/tmp/sdl3_ttf_src"
        self.sdl_ttf_build = "/tmp/sdl3_ttf_src/build"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return (
            self.connection.run_return_code(["pkg-config", "--exists", "sdl3"]) == 0 and
            self.connection.run_return_code(["pkg-config", "--exists", "sdl3-ttf"]) == 0)

    def _build_and_install(self, repo, tag, src, build, configure_args):
        self.connection.remove_file_or_directory(src)
        self.connection.run_checked([
            "git", "clone", "--depth", "1", "--branch", tag, repo, src])
        self.connection.run_checked([
            "cmake", "-S", src, "-B", build,
            "-DCMAKE_BUILD_TYPE=Release"] + configure_args)
        self.connection.run_checked(["cmake", "--build", build, "--parallel"])
        self.connection.run_checked(["cmake", "--install", build], sudo = True)
        self.connection.remove_file_or_directory(src)

    def install(self):

        # Start install
        util.log_info("Installing SDL3")

        # Build SDL3
        util.log_info("Building SDL3")
        self._build_and_install(
            self.sdl_repo, self.sdl_tag, self.sdl_src, self.sdl_build,
            ["-DSDL_SHARED=ON", "-DSDL_STATIC=OFF", "-DSDL_TEST_LIBRARY=OFF"])

        # Build SDL3_ttf
        util.log_info("Building SDL3_ttf")
        self._build_and_install(
            self.sdl_ttf_repo, self.sdl_ttf_tag, self.sdl_ttf_src, self.sdl_ttf_build,
            ["-DSDLTTF_VENDORED=OFF", "-DSDLTTF_HARFBUZZ=OFF",
             "-DSDLTTF_PLUTOSVG=OFF", "-DSDLTTF_SAMPLES=OFF"])

        # Refresh the shared library cache
        util.log_info("Refreshing shared library cache")
        self.connection.run_checked(["ldconfig"], sudo = True)

        # All done
        util.log_info("SDL3 installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling SDL3")

        # Remove files
        for path in [
            "/usr/local/lib/cmake/SDL3",
            "/usr/local/lib/cmake/SDL3_ttf",
            "/usr/local/include/SDL3",
            "/usr/local/lib/pkgconfig/sdl3.pc",
            "/usr/local/lib/pkgconfig/sdl3-ttf.pc",
            "/usr/local/lib/libSDL3*",
            "/usr/local/lib/libSDL3_ttf*"]:
            self.connection.remove_file_or_directory(path, sudo = True)

        # Refresh the shared library cache
        util.log_info("Refreshing shared library cache")
        self.connection.run_checked(["ldconfig"], sudo = True)

        # All done
        util.log_info("SDL3 uninstalled")
        return True
