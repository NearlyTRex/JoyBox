# Imports
import types

# Local imports
from joybox import config
from joybox import settings
from joybox import storebase
from joybox import paths

# Zoom store
class Zoom(storebase.StoreBase):

    TYPE = config.StoreType.ZOOM
    PLATFORM = config.Platform.COMPUTER_ZOOM
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_ZOOM
    KEY = config.JSON_KEY_ZOOM
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_NAME,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.Zoom", "zoom_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    ############################################################
