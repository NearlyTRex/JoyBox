# Managed blocks in configuration files.
#
# A block of generated content bracketed by marker lines, so it can be
# replaced or removed later without disturbing whatever else the file holds.
# Used for /etc/hosts entries, the sshd drop-in, and the dotfiles block in a
# user's .bashrc.

# Find a managed block
def find_block(contents, begin_marker, end_marker):
    if not isinstance(contents, str):
        return (-1, -1)
    begin_index = contents.find(begin_marker)
    if begin_index < 0:
        return (-1, -1)
    end_index = contents.find(end_marker, begin_index + len(begin_marker))
    if end_index < 0:
        return (-1, -1)
    return (begin_index, end_index + len(end_marker))

# Check if a managed block is present
def has_block(contents, begin_marker, end_marker):
    return find_block(contents, begin_marker, end_marker) != (-1, -1)

# Remove a managed block, leaving the rest of the file as it was
def remove_block(contents, begin_marker, end_marker):
    if not isinstance(contents, str):
        return ""
    begin_index, end_index = find_block(contents, begin_marker, end_marker)
    if begin_index < 0:
        return contents
    before = contents[:begin_index].rstrip()
    after = contents[end_index:].lstrip("\n")
    if before and after:
        return before + "\n\n" + after
    if before:
        return before + "\n"
    return after

# Build a managed block from its body
def build_block(body, begin_marker, end_marker, note = None):
    lines = [begin_marker]
    if note:
        lines.append(note)
    if isinstance(body, (list, tuple)):
        body = "\n".join(str(line) for line in body)
    body = (body or "").rstrip()
    if body:
        lines.append(body)
    lines.append(end_marker)
    return "\n".join(lines)

# Replace a managed block, or append one when the file has none. Running this
# twice with the same body leaves the file unchanged.
def set_block(contents, body, begin_marker, end_marker, note = None):
    base = remove_block(contents or "", begin_marker, end_marker).rstrip()
    block = build_block(body, begin_marker, end_marker, note)
    if base:
        return base + "\n\n" + block + "\n"
    return block + "\n"

# Read the body of a managed block, without its markers or note
def read_block_body(contents, begin_marker, end_marker, note = None):
    begin_index, end_index = find_block(contents, begin_marker, end_marker)
    if begin_index < 0:
        return None
    inner = contents[begin_index + len(begin_marker):end_index - len(end_marker)]
    lines = inner.strip("\n").splitlines()
    if note and lines and lines[0] == note:
        lines = lines[1:]
    return "\n".join(lines)
