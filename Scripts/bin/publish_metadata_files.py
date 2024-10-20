#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Publish metadata files.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# HTML templates
html_header = """
<html>
<head>
<title>Game List - %s</title>
<style type="text/css">
table {
    border-collapse: collapse;
    border-color: #93a1a1;
    border-spacing: 0;
}
th {
    background-color: #657b83;
    border-color: #93a1a1;
    border-style: solid;
    border-width: 1px;
    color: #fdf6e3;
    font-family: Arial,sans-serif;
    font-size: 14px;
    font-weight: normal;
    overflow: hidden;
    padding: 2px 11px;
    word-break: normal;
}
td {
    border-color: #93a1a1;
    border-style: solid;
    border-width: 1px;
    color: #002b36;
    font-family: Arial,sans-serif;
    font-size: 14px;
    overflow: hidden;
    padding: 2px 11px;
    word-break: normal;
    text-align: left;
    vertical-align: top;
}
tr:nth-child(even) {
    background-color: #eee8d5;
}
tr:nth-child(odd) {
    background-color: #fdf6e3;
}
</style>
<script src="lib/sorttable.js"></script>
</head>
<body>
<table class="sortable">
<thead>
<tr>
<th>ID</th>
<th>Platform</th>
<th>Title</th>
<th>Players</th>
<th>Co-op</th>
<th>Information</th>
</tr>
</thead>
<tbody>
"""
html_footer = """
</tbody>
</table>
</body>
</html>
"""
html_entry_odd = """
<tr>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>
<a href="https://gamefaqs.gamespot.com/search?game=%s" target="_blank">GameFAQs</a>
&nbsp;&#124;&nbsp;
<a href="https://www.mobygames.com/search/quick?q=%s" target="_blank">MobyGames</a>
</td>
</tr>
"""
html_entry_even = """
<tr>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>
<a href="https://gamefaqs.gamespot.com/search?game=%s" target="_blank">GameFAQs</a>
&nbsp;&#124;&nbsp;
<a href="https://www.mobygames.com/search/quick?q=%s" target="_blank">MobyGames</a>
</td>
</tr>
"""

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Build new published file for each category
    for game_category in config.game_categories:

        # Reset odd/even counter
        metadata_counter = 1
        metadata_publish_file = os.path.join(environment.GetPublishedMetadataRootDir(), game_category + ".html")

        # Open new file
        with open(metadata_publish_file, "w", encoding="utf8") as file:

            # Write header
            file.write(html_header % game_category)
            for game_subcategory in config.game_subcategories[game_category]:

                # Get metadata contents
                metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
                if os.path.isfile(metadata_file):
                    metadata_obj = metadata.Metadata()
                    metadata_obj.import_from_metadata_file(metadata_file)

                    # Iterate through each platform/entry
                    for game_platform in metadata_obj.get_sorted_platforms():
                        game_entry_id = 1
                        for game_entry in metadata_obj.get_sorted_entries(game_platform):

                                # Get entry info
                                game_entry_name = game_entry.get_game()
                                game_entry_players = game_entry.get_players()
                                game_entry_coop = game_entry.get_coop()
                                game_entry_urlname = system.EncodeUrlString(game_entry_name)
                                game_entry_info = (
                                    game_entry_id,
                                    game_platform,
                                    game_entry_name,
                                    game_entry_players,
                                    game_entry_coop,
                                    game_entry_urlname,
                                    game_entry_urlname
                                )

                                # Write entry (using odd/even templates)
                                if (metadata_counter % 2) == 0:
                                    file.write(html_entry_even % game_entry_info)
                                else:
                                    file.write(html_entry_odd % game_entry_info)
                                metadata_counter += 1
                                game_entry_id += 1

            # Write footer
            file.write(html_footer)

# Start
main()
