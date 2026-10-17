###########################################################
# Package list files
#
# serverpackages.txt and servermanagers.txt are plain lists with # comments.
###########################################################

def parse_package_text_file(path):
    entries = []
    with open(path, "r", encoding = "utf-8") as package_file:
        for line in package_file:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries
