# Local imports
from joybox import config
from joybox import storebase

# RedCandle store
class RedCandle(storebase.StoreBase):

    TYPE = config.StoreType.RED_CANDLE
    PLATFORM = config.Platform.COMPUTER_RED_CANDLE
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_RED_CANDLE
    KEY = config.JSON_KEY_REDCANDLE
    IDENTIFIER_KEYS = storebase.NAME_IDENTIFIER_KEYS

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.load_install_dir("UserData.RedCandle", "redcandle_install_dir")

    ############################################################
    # Store
    ############################################################

    ############################################################
