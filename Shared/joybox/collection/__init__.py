# Imports
from joybox.collection.asset import *
from joybox.collection.backup import *
from joybox.collection.hashing import *
from joybox.collection.installing import *
from joybox.collection.jsondata import *
from joybox.collection.launching import *
from joybox.collection.metadata import *
from joybox.collection.purchase import *
from joybox.collection.saves import *
from joybox.collection.uploading import *

# Submodule handles
import sys as _sys
asset = _sys.modules["joybox.collection.asset"]
backup = _sys.modules["joybox.collection.backup"]
hashing = _sys.modules["joybox.collection.hashing"]
installing = _sys.modules["joybox.collection.installing"]
jsondata = _sys.modules["joybox.collection.jsondata"]
launching = _sys.modules["joybox.collection.launching"]
metadata = _sys.modules["joybox.collection.metadata"]
purchase = _sys.modules["joybox.collection.purchase"]
saves = _sys.modules["joybox.collection.saves"]
uploading = _sys.modules["joybox.collection.uploading"]
del _sys
