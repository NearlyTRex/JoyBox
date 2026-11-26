# Local imports
from joybox import config
from joybox import settings
from joybox import storebase
from joybox import paths

# RedCandle store
class RedCandle(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.RedCandle", "redcandle_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return config.StoreType.RED_CANDLE.val()

    # Get type
    def get_type(self):
        return config.StoreType.RED_CANDLE

    # Get platform
    def get_platform(self):
        return config.Platform.COMPUTER_RED_CANDLE

    # Get supercategory
    def get_supercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def get_category(self):
        return config.Category.COMPUTER

    # Get subcategory
    def get_subcategory(self):
        return config.Subcategory.COMPUTER_RED_CANDLE

    # Get key
    def get_key(self):
        return config.JSON_KEY_REDCANDLE

    # Get identifier keys
    def get_identifier_keys(self):
        return {
            config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_NAME,
            config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_NAME,
            config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_NAME,
            config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_NAME,
            config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_NAME,
            config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_NAME,
            config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_NAME
        }

    # Get install dir
    def get_install_dir(self):
        return self.install_dir

    ############################################################
