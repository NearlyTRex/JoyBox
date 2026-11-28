# Local imports
from joybox import config
from joybox import storebase

# SquareEnix store
class SquareEnix(storebase.StoreBase):

    TYPE = config.StoreType.SQUARE_ENIX
    PLATFORM = config.Platform.COMPUTER_SQUARE_ENIX
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_SQUARE_ENIX
    KEY = config.JSON_KEY_SQUAREENIX
    IDENTIFIER_KEYS = storebase.NAME_IDENTIFIER_KEYS

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.load_install_dir("UserData.SquareEnix", "squareenix_install_dir")

    ############################################################
    # Store
    ############################################################

    ############################################################
