# Imports
from . import dxvk
from . import vkd3d

# Third-party library instances
instances = [
    dxvk.DXVK(),
    vkd3d.VKD3D(),
]

# Get third-party libraries
def GetThirdPartyLibraries():
    return instances
