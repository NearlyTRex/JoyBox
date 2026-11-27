# Local imports
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from . import installer

# SDL3 and SDL3_ttf, built from source since Ubuntu/Mint do not package them yet,
# for emulators ported off SDL2 such as PPSSPP master; installed to /usr/local so
# CMake's find_package finds them
class Sdl3(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

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

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Whether pkg-config finds both sdl3 and sdl3-ttf
    def is_installed(self):
        return (
            self.connection.run_return_code(["pkg-config", "--exists", "sdl3"]) == 0 and
            self.connection.run_return_code(["pkg-config", "--exists", "sdl3-ttf"]) == 0)

    def _build_and_install(self, repo, tag, src, build, configure_args):
        self.connection.remove_file_or_directory(src)
        self.connection.run_checked([
            self.git_tool, "clone", "--depth", "1", "--branch", tag, repo, src])
        self.connection.run_checked([
            self.cmake_tool, "-S", src, "-B", build,
            "-DCMAKE_BUILD_TYPE=Release"] + configure_args)
        self.connection.run_checked([self.cmake_tool, "--build", build, "--parallel"])
        self.connection.run_checked([self.cmake_tool, "--install", build], sudo = True)
        self.connection.remove_file_or_directory(src)

    # Clone, build and install the pinned SDL3 then SDL3_ttf releases into
    # /usr/local, then run ldconfig
    def install(self):

        # Start install
        logger.log_info("Installing SDL3")

        # Build SDL3
        logger.log_info("Building SDL3")
        self._build_and_install(
            self.sdl_repo, self.sdl_tag, self.sdl_src, self.sdl_build,
            ["-DSDL_SHARED=ON", "-DSDL_STATIC=OFF", "-DSDL_TEST_LIBRARY=OFF"])

        # Build SDL3_ttf
        logger.log_info("Building SDL3_ttf")
        self._build_and_install(
            self.sdl_ttf_repo, self.sdl_ttf_tag, self.sdl_ttf_src, self.sdl_ttf_build,
            ["-DSDLTTF_VENDORED=OFF", "-DSDLTTF_HARFBUZZ=OFF",
             "-DSDLTTF_PLUTOSVG=OFF", "-DSDLTTF_SAMPLES=OFF"])

        # Refresh the shared library cache
        logger.log_info("Refreshing shared library cache")
        self.connection.run_checked(["ldconfig"], sudo = True)

        # All done
        logger.log_info("SDL3 installed successfully")
        return True

    # Delete the SDL3 and SDL3_ttf headers, libraries, CMake and pkg-config files
    # from /usr/local, then run ldconfig
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling SDL3")

        # Remove files
        for path in [
            "/usr/local/lib/cmake/SDL3",
            "/usr/local/lib/cmake/SDL3_ttf",
            "/usr/local/include/SDL3",
            "/usr/local/lib/pkgconfig/sdl3.pc",
            "/usr/local/lib/pkgconfig/sdl3-ttf.pc"]:
            self.connection.remove_file_or_directory(path, sudo = True)

        # Remove the libSDL3 and libSDL3_ttf libraries and symlinks; commands run
        # without a shell, so find matches the pattern
        self.connection.run_checked([
            "find", "/usr/local/lib", "-maxdepth", "1", "-name", "libSDL3*", "-delete"], sudo = True)

        # Refresh the shared library cache
        logger.log_info("Refreshing shared library cache")
        self.connection.run_checked(["ldconfig"], sudo = True)

        # All done
        logger.log_info("SDL3 uninstalled")
        return True
