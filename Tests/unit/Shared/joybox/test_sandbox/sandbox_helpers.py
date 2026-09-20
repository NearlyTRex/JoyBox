# Imports
from joybox import commandoptions


###########################################################
# Prefix options
#
# Wine and Sandboxie lay out a prefix differently, and every path a game is
# given is resolved through these. A wrong drive or profile path writes a save
# outside the prefix.
###########################################################

PREFIX = "/prefixes/game"


def options(wine = False, sandboxie = False, prefix_dir = PREFIX, prefix_name = None):
    entry = commandoptions.CommandOptions()
    entry.set_is_wine_prefix(wine)
    entry.set_is_sandboxie_prefix(sandboxie)
    if prefix_dir:
        entry.set_prefix_dir(prefix_dir)
    if prefix_name:
        entry.set_prefix_name(prefix_name)
    return entry


WINE = lambda **kwargs: options(wine = True, **kwargs)
SANDBOXIE = lambda **kwargs: options(sandboxie = True, **kwargs)
NEITHER = lambda **kwargs: options(**kwargs)
