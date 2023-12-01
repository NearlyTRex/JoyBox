import os, os.path
from xml.dom import minidom

f = open("datfile_tsv.txt", "w", encoding='utf-8', errors='ignore')

for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name.endswith(".tsv"):
            with open(os.path.join(root, name), "r", encoding='utf-8', errors='ignore') as tsv:
                tsv_lines = tsv.readlines()
                for tsv_line in tsv_lines:
                    tsv_tokens = tsv_line.strip("\n").split("\t")
                    if len(tsv_tokens) < 9:
                        print("Skipping " + tsv_line)
                        continue
                    entry = {}
                    entry["type"] = name
                    entry["title_id"] = tsv_tokens[0]
                    entry["region"] = tsv_tokens[1]
                    if entry["region"] == "US":
                        entry["region"] = "USA"
                    elif entry["region"] == "EU":
                        entry["region"] = "Europe"
                    elif entry["region"] == "ASIA":
                        entry["region"] = "Asia"
                    elif entry["region"] == "JP":
                        entry["region"] = "Japan"
                    entry["name"] = tsv_tokens[2].replace(": ", " - ").replace("?", "").replace("/", " - ").replace("\"", "'")
                    entry["pkg_link"] = tsv_tokens[3]
                    entry["pkg_file"] = tsv_tokens[3][tsv_tokens[3].rfind("/") + 1 : len(tsv_tokens[3])]
                    entry["key"] = tsv_tokens[4]
                    entry["content_id"] = tsv_tokens[5]
                    entry["date"] = tsv_tokens[6]
                    entry["file_size"] = tsv_tokens[7]
                    if len(tsv_tokens[8]) == 0:
                        entry["sha256"] = "MISSING"
                    else:
                        entry["sha256"] = tsv_tokens[8].upper()
                    if len(entry["sha256"]) == 0:
                        continue
                    if not entry["pkg_link"].startswith("http"):
                        continue
                    dat_name = entry["title_id"] + " - " + entry["name"] + " (" + entry["region"] + ")" + " (" + entry["type"] + ")"
                    dat_file = entry["pkg_file"]
                    dat_md5 = "MISSING"
                    dat_sha256 = entry["sha256"]
                    f.write("%s || %s || %s || %s\n" % (dat_name, dat_file, dat_md5, dat_sha256))
f.close()
