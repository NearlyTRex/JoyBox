# Imports
import dxvk
import vkd3d

# Get third-party libraries
def GetThirdPartyLibraries():
    return [
        dxvk.DXVK(),
        vkd3d.VKD3D(),
    ]
