###########################################################
# Install images
#
# Shared by the unit and integration tests of joybox.install.
###########################################################

# Write each relative path under root with content naming it
def make_tree(root, *relative_paths):
    for relative in relative_paths:
        target = root / relative
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_text("content of %s\n" % relative)
    return root


# A Wine prefix holding only game files
def make_prefix(tmp_path):
    root = tmp_path / "prefix"
    root.mkdir()
    return make_tree(
        root,
        "Program Files/Game/game.exe",
        "Program Files/Game/data/assets.pak",
        "ProgramData/Game/settings.ini")
