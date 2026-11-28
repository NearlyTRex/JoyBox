# Local imports
from joybox import config
from joybox import storebase

# Zoom store
class Zoom(storebase.StoreBase):

    TYPE = config.StoreType.ZOOM
    PLATFORM = config.Platform.COMPUTER_ZOOM
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_ZOOM
    KEY = config.JSON_KEY_ZOOM
    IDENTIFIER_KEYS = storebase.NAME_IDENTIFIER_KEYS

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.load_install_dir("UserData.Zoom", "zoom_install_dir")

    ############################################################
    # Store
    ############################################################

    ############################################################
