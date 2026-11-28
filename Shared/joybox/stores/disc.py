# Local imports
from joybox import config
from joybox import storebase

# Disc store
class Disc(storebase.StoreBase):

    TYPE = config.StoreType.DISC
    PLATFORM = config.Platform.COMPUTER_DISC
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_DISC
    KEY = config.JSON_KEY_DISC
    IDENTIFIER_KEYS = storebase.NAME_IDENTIFIER_KEYS

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.load_install_dir("UserData.Disc", "disc_install_dir")

    ############################################################
    # Store
    ############################################################

    ############################################################
