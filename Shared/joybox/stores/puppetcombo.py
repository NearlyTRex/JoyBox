# Local imports
from joybox import config
from joybox import storebase

# PuppetCombo store
class PuppetCombo(storebase.StoreBase):

    TYPE = config.StoreType.PUPPET_COMBO
    PLATFORM = config.Platform.COMPUTER_PUPPET_COMBO
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_PUPPET_COMBO
    KEY = config.JSON_KEY_PUPPETCOMBO
    IDENTIFIER_KEYS = storebase.NAME_IDENTIFIER_KEYS

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.load_install_dir("UserData.PuppetCombo", "puppetcombo_install_dir")

    ############################################################
    # Store
    ############################################################

    ############################################################
