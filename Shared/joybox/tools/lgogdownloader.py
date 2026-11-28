# Local imports
from joybox import toolbase
from joybox import platform_info


# LGOGDownloader tool
class LGOGDownloader(toolbase.ToolBase):

    NAME = "LGOGDownloader"

    # On Linux, write its config files under the tools root
    def configure(self, setup_params = None):
        if not platform_info.is_linux_platform():
            return True
        return self.write_config_files(setup_params)
