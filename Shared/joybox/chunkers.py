# Imports
import json
import os
import re

# Local imports
import joybox.logger as logger

###########################################################
# Chunkers
###########################################################

# A chunker knows how to summarise one kind of file without carrying its
# body, and how to name the regions inside it. That pairing is what lets a
# file far larger than a context window stay usable: send the outline, then
# fetch only the region that matters.
#
# Each chunker provides:
#   marks(lines)    -> [(line_number, label)]     the map
#   regions(lines)  -> {name: (start, end)}       addressable spans
#
# Register a new one by subclassing Chunker and listing its extensions.

# Maximum marks in an outline before it is thinned; an outline is a map,
# not a transcript.
MAX_MARKS = 120

# Base chunker
class Chunker:
    name = "text"
    extensions = ()

    # Structural points of interest, as (line_number, label)
    def marks(self, lines):
        return []

    # Named spans, as {name: (start_line, end_line)}, both inclusive
    def regions(self, lines):
        found = self.marks(lines)
        out = {}
        for index, (line_number, label) in enumerate(found):
            end = found[index + 1][0] - 1 if index + 1 < len(found) else len(lines)
            out[self.region_name(label, line_number)] = (line_number, end)
        return out

    # How a region is addressed by a reader
    def region_name(self, label, line_number):
        slug = re.sub(r"[^A-Za-z0-9_.]+", "_", label).strip("_")
        return slug[:48] or f"line_{line_number}"

    # Thin an over-long map so it stays a map
    def thin(self, found):
        if len(found) <= MAX_MARKS:
            return found
        step = len(found) // MAX_MARKS + 1
        return found[::step]

###########################################################
# Assembly
###########################################################

# Watcom/Ghidra assembly listings: branch labels and call targets are the
# structure, and the header comment block carries the signature and locals.
class AsmChunker(Chunker):
    name = "asm"
    extensions = (".asm", ".s", ".nasm")

    LABEL = re.compile(r"^\s*(LAB_[0-9A-Fa-f]+|[A-Za-z_.$][\w.$]*):")
    TARGET = re.compile(r"\b(?:CALL|JMP)\s+([A-Za-z_.$][\w.$]*)")
    XREF = re.compile(r";\s*XREF.*?(LAB_[0-9A-Fa-f]+)")

    def marks(self, lines):
        found = []
        in_header = True
        for number, line in enumerate(lines, start = 1):
            stripped = line.strip()
            if in_header and stripped and not stripped.startswith(";"):
                found.append((number, "-- code begins --"))
                in_header = False
            if not stripped:
                continue
            match = self.LABEL.match(line)
            if match:
                found.append((number, match.group(1)))
                continue
            match = self.XREF.search(line)
            if match:
                found.append((number, match.group(1)))
                continue
            match = self.TARGET.search(line)
            if match and match.group(1) not in ("CALL", "JMP"):
                found.append((number, f"-> {match.group(1)}"))
        return self.thin(found)

###########################################################
# C and C++
###########################################################

# Definitions at column zero are the structure. Ghidra output is one
# function per file more often than not, so type and global declarations
# matter as much as the function itself.
class CChunker(Chunker):
    name = "c"
    extensions = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".keep")

    FUNCTION = re.compile(r"^[A-Za-z_][\w *&:<>~,\[\]]*\([^;]*\)\s*(?:const\s*)?\{?\s*$")
    TYPE = re.compile(r"^\s*(?:typedef\s+)?(struct|union|enum|class)\s+([A-Za-z_]\w*)")
    LABEL_COMMENT = re.compile(r"^\s*//\s*(Name|Signature|Address|Convention):\s*(.+)$")

    def marks(self, lines):
        found = []
        for number, line in enumerate(lines, start = 1):
            match = self.LABEL_COMMENT.match(line)
            if match:
                found.append((number, f"{match.group(1)}: {match.group(2)[:60]}"))
                continue
            match = self.TYPE.match(line)
            if match:
                found.append((number, f"{match.group(1)} {match.group(2)}"))
                continue
            if line and not line[0].isspace() and self.FUNCTION.match(line):
                found.append((number, line.strip()[:70]))
        return self.thin(found)

###########################################################
# JSON
###########################################################

# Top-level keys, with the shape and size of each value, so a reader can
# ask for one branch rather than the document.
class JsonChunker(Chunker):
    name = "json"
    extensions = (".json",)

    KEY = re.compile(r'^\s{0,4}"([^"]+)"\s*:')

    def describe(self, value):
        if isinstance(value, dict):
            return f"object, {len(value)} keys"
        if isinstance(value, list):
            return f"array, {len(value)} items"
        if isinstance(value, str):
            return f"string, {len(value)} chars"
        return type(value).__name__

    def marks(self, lines):
        text = "\n".join(lines)
        summary = {}
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                summary = {key: self.describe(value) for key, value in data.items()}
        except (json.JSONDecodeError, ValueError):
            pass

        found = []
        seen = set()
        for number, line in enumerate(lines, start = 1):
            match = self.KEY.match(line)
            if not match:
                continue
            key = match.group(1)
            if key in seen:
                continue
            seen.add(key)
            note = f" ({summary[key]})" if key in summary else ""
            found.append((number, f"{key}{note}"))
        return self.thin(found)

###########################################################
# Markdown
###########################################################

# Headings, with their level preserved so nesting is visible.
class MarkdownChunker(Chunker):
    name = "markdown"
    extensions = (".md", ".markdown")

    HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

    def marks(self, lines):
        found = []
        in_fence = False
        for number, line in enumerate(lines, start = 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            match = self.HEADING.match(line)
            if match:
                depth = len(match.group(1))
                found.append((number, f"{'  ' * (depth - 1)}{match.group(2)[:64]}"))
        return self.thin(found)

###########################################################
# Python
###########################################################
class PythonChunker(Chunker):
    name = "python"
    extensions = (".py",)

    DEF = re.compile(r"^(\s*)(def|class)\s+([A-Za-z_]\w*)")

    def marks(self, lines):
        found = []
        for number, line in enumerate(lines, start = 1):
            match = self.DEF.match(line)
            if match:
                indent = "  " if match.group(1) else ""
                found.append((number, f"{indent}{match.group(2)} {match.group(3)}"))
        return self.thin(found)

###########################################################
# Fallback
###########################################################

# No structure to key on, so offer fixed windows. Better than nothing: a
# reader can still ask for a numbered slice.
class LineChunker(Chunker):
    name = "lines"
    extensions = ()
    WINDOW = 200

    def marks(self, lines):
        found = []
        for start in range(1, len(lines) + 1, self.WINDOW):
            end = min(start + self.WINDOW - 1, len(lines))
            found.append((start, f"lines {start}-{end}"))
        return self.thin(found)

###########################################################
# Registry
###########################################################
REGISTERED = [AsmChunker, CChunker, JsonChunker, MarkdownChunker, PythonChunker]
FALLBACK = LineChunker

# Look up the chunker for a path by extension
def get_chunker(path):
    extension = os.path.splitext(path)[1].lower()
    for cls in REGISTERED:
        if extension in cls.extensions:
            return cls()
    return FALLBACK()

# Add a chunker at runtime, so a project can register its own
def register_chunker(cls):
    if cls not in REGISTERED:
        REGISTERED.insert(0, cls)
    return cls

# Names of every registered chunker, for display
def list_chunkers():
    entries = []
    for cls in REGISTERED + [FALLBACK]:
        entries.append((cls.name, ", ".join(cls.extensions) or "(fallback)"))
    return entries

###########################################################
# Rendering
###########################################################

# Read a file, tolerating whatever encoding it turns out to be
def read_lines(path):
    with open(path, "r", encoding = "utf-8", errors = "replace") as handle:
        return handle.read().splitlines()

# A map of the file: structure and line numbers, no body
def outline(path, header = True):
    lines = read_lines(path)
    chunker = get_chunker(path)
    found = chunker.marks(lines)

    body = "\n".join(f"{number:>6}  {label}" for number, label in found)
    if not body:
        body = "  (no structure found)"

    if not header:
        return body
    return (f"### Outline of {os.path.basename(path)}  "
            f"({len(lines)} lines, {chunker.name} chunker)\n\n"
            f"This is a map, not the contents. Ask for a line range or a "
            f"region name and I will supply it.\n\n```\n{body}\n```")

# Turn 120-260, 120-, -260 or 120 into a pair of line numbers. Raises
# ValueError on anything else, so a caller can report it.
def parse_range(spec):
    if not spec:
        return 0, 0
    if "-" not in spec:
        value = int(spec)
        return value, value
    start, _, end = spec.partition("-")
    return (int(start) if start.strip() else 0), (int(end) if end.strip() else 0)

# A slice of the file, numbered so a follow-up can name lines
def slice_lines(path, start = 0, end = 0, header = True):
    lines = read_lines(path)
    total = len(lines)
    start = max(1, start or 1)
    end = min(total, end or total)
    if start > total:
        return ""

    body = "\n".join(f"{start + offset:>6}  {text}"
                     for offset, text in enumerate(lines[start - 1:end]))
    if not header:
        return body

    extension = os.path.splitext(path)[1].lstrip(".") or "text"
    return (f"### {os.path.basename(path)}  (lines {start}-{end} of {total})\n\n"
            f"```{extension}\n{body}\n```")

# A named region, as the chunker for this filetype defines them
def slice_region(path, name):
    lines = read_lines(path)
    spans = get_chunker(path).regions(lines)
    if name in spans:
        start, end = spans[name]
        return slice_lines(path, start, end)

    # Accept a unique partial match, since region names can be long
    matches = [key for key in spans if name.lower() in key.lower()]
    if len(matches) == 1:
        start, end = spans[matches[0]]
        return slice_lines(path, start, end)
    if len(matches) > 1:
        logger.log_warning(f"Ambiguous region '{name}': {', '.join(matches[:6])}")
    return ""

# Region names available in a file
def list_regions(path):
    return sorted(get_chunker(path).regions(read_lines(path)))

# Whole file, rendered as a fenced block
def render_file(path):
    extension = os.path.splitext(path)[1].lstrip(".") or "text"
    lines = read_lines(path)
    return (f"### {os.path.basename(path)}  ({len(lines)} lines)\n\n"
            f"```{extension}\n" + "\n".join(lines).rstrip() + "\n```")

# Rough token estimate for dense technical text
def estimate_tokens(text):
    return int(len(text) / 3.6)
