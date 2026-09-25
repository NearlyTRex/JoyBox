# Imports
import os

# Get the checkout's Bootstrap directory, which holds the data the installers
# ship: day-0 scripts, managers, dotfiles and seed content
def get_data_dir():
    return os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "Bootstrap"))
