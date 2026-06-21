# Imports
import os
import sys

# Publish templates
publish_html_header = """
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
publish_html_footer = """
</tbody>
</table>
</body>
</html>
"""
publish_html_entry_odd = """
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
publish_html_entry_even = """
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
