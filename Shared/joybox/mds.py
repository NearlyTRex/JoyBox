# Imports
import re
import struct

# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.serialization as serialization

# Alcohol 120% media descriptor (.mds) beside its data file (.mdf), read as
# libmirage reads it; only version 1 descriptors have a known layout
mds_signature = b"MEDIA DESCRIPTOR"
mds_version_major = 1

# Medium types
mds_cd_media = (0x00, 0x01, 0x02)
mds_dvd_media = (0x10, 0x12)

# Header fields
mds_medium_offset = 0x12
mds_sessions_offset = 0x50

# Blocks
mds_session_block = struct.Struct("<iiHBBHHII")
mds_track_block = struct.Struct("<12BIH18xIQII24x")
mds_extra_block = struct.Struct("<II")
mds_footer_block = struct.Struct("<IIII")

# Interleaved PW subchannel follows the main data of every sector
mds_subchannel_none = 0x00
mds_subchannel_pw = 0x08
mds_subchannel_size = 96

# Track modes; Alcohol reads only the low three bits
mds_track_modes = {
    0: "MODE2",
    1: "AUDIO",
    2: "MODE1",
    3: "MODE2",
    4: "MODE2_FORM1",
    5: "MODE2_FORM2",
    7: "MODE2",
}

# Cue track types chdman accepts, by track mode and stored main data size
cue_track_types = {
    ("AUDIO", 2352): "AUDIO",
    ("MODE1", 2048): "MODE1/2048",
    ("MODE1", 2352): "MODE1/2352",
    ("MODE2", 2336): "MODE2/2336",
    ("MODE2", 2352): "MODE2/2352",
    ("MODE2_FORM1", 2048): "MODE2/2048",
    ("MODE2_FORM1", 2336): "MODE2/2336",
    ("MODE2_FORM1", 2352): "MODE2/2352",
    ("MODE2_FORM2", 2324): "MODE2/2324",
    ("MODE2_FORM2", 2336): "MODE2/2336",
    ("MODE2_FORM2", 2352): "MODE2/2352",
}

# Two seconds of pregap lead every disc and a cue leaves them implicit
standard_first_pregap = 150

# Frames per second of cd time
cd_frames_per_second = 75

###########################################################

# Raised for a descriptor that cannot be converted
class MdsError(ValueError):
    pass

# Read the data file name a footer points at
def read_mds_filename(data, offset, widechar):
    if widechar:
        end = offset
        while data[end:end + 2] != b"\0\0":
            if end >= len(data):
                raise MdsError("data file name runs past the end of the descriptor")
            end += 2
        return data[offset:end].decode("utf-16-le")
    end = data.find(b"\0", offset)
    if end < 0:
        raise MdsError("data file name runs past the end of the descriptor")
    return data[offset:end].decode("cp1252", errors = "replace")

# Find the data file a descriptor names, beside the descriptor
# "*.mdf" means the descriptor's own name with that extension
def resolve_mdf_file(mds_file, declared_name):
    mds_dir = paths.get_filename_directory(mds_file)
    wildcard = re.fullmatch(r"\*(\.\w+)", declared_name)
    if wildcard:
        wanted_name = paths.get_filename_basename(mds_file) + wildcard.group(1)
    else:
        wanted_name = declared_name.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = paths.join_paths(mds_dir, wanted_name)
    if paths.is_path_file(candidate):
        return candidate
    for obj in paths.get_directory_contents(mds_dir):
        if obj.lower() == wanted_name.lower() and paths.is_path_file(paths.join_paths(mds_dir, obj)):
            return paths.join_paths(mds_dir, obj)
    raise MdsError("data file %s was not found" % candidate)

# Parse the header, returning whether the medium is a dvd
def parse_mds_header(data):
    if data[:len(mds_signature)] != mds_signature:
        raise MdsError("not a media descriptor")
    if data[16] != mds_version_major:
        raise MdsError("version %d.%d descriptors are not supported" % (data[16], data[17]))
    medium_type, num_sessions = struct.unpack_from("<HH", data, mds_medium_offset)
    if medium_type not in mds_cd_media + mds_dvd_media:
        raise MdsError("medium type 0x%02X is not supported" % medium_type)
    if num_sessions != 1:
        raise MdsError("%d sessions; only single-session discs are supported" % num_sessions)
    return medium_type in mds_dvd_media

# Get the sector layout of a track as (mode, cue type, main size, subchannel size)
def get_mds_track_layout(point, mode, subchannel, sector_size, is_dvd):
    track_mode = mds_track_modes.get(mode & 0x07)
    if track_mode is None:
        raise MdsError("track %d has unknown mode 0x%02X" % (point, mode))
    subchannel_sizes = {mds_subchannel_none: 0, mds_subchannel_pw: mds_subchannel_size}
    if subchannel not in subchannel_sizes:
        raise MdsError("track %d has unknown subchannel type 0x%02X" % (point, subchannel))
    main_size = sector_size - subchannel_sizes[subchannel]
    if is_dvd and main_size == 2048:
        track_mode = "MODE1"
    cue_type = cue_track_types.get((track_mode, main_size))
    if cue_type is None:
        raise MdsError("track %d is %s with %d-byte sectors, which a cue sheet cannot describe" % (point, track_mode, main_size))
    return track_mode, cue_type, main_size, subchannel_sizes[subchannel]

# Get the (pregap, length) of a track; a cd keeps them in the extra block, a dvd fills the rest of its file
def get_mds_track_length(data, point, extra_offset, data_file, start_offset, sector_size, is_dvd):
    if is_dvd:
        pregap, length = 0, (paths.get_file_size(data_file) - start_offset) // sector_size
    elif not extra_offset:
        raise MdsError("track %d has no length" % point)
    else:
        pregap, length = mds_extra_block.unpack_from(data, extra_offset)
    if length <= 0:
        raise MdsError("track %d is empty" % point)
    return pregap, length

# Parse a track block, or None for a block that describes the lead-in
def parse_mds_track(data, block_offset, mds_file, is_dvd):
    fields = mds_track_block.unpack_from(data, block_offset)
    mode, subchannel, point = fields[0], fields[1], fields[4]
    extra_offset, sector_size, _, start_offset, number_of_files, footer_offset = fields[12:18]
    if not 1 <= point <= 99:
        return None
    track_mode, cue_type, main_size, subchannel_size = get_mds_track_layout(point, mode, subchannel, sector_size, is_dvd)
    if number_of_files != 1:
        raise MdsError("track %d is split over %d data files, which is not supported" % (point, number_of_files))
    filename_offset, widechar, _, _ = mds_footer_block.unpack_from(data, footer_offset)
    data_file = resolve_mdf_file(mds_file, read_mds_filename(data, filename_offset, widechar))
    pregap, length = get_mds_track_length(data, point, extra_offset, data_file, start_offset, sector_size, is_dvd)
    return {
        "number": point,
        "mode": track_mode,
        "cue_type": cue_type,
        "sector_size": sector_size,
        "main_size": main_size,
        "subchannel_size": subchannel_size,
        "start_offset": start_offset,
        "length": length,
        "pregap": pregap,
        "data_file": data_file,
    }

# Parse a descriptor into its medium and tracks
def parse_mds_descriptor(data, mds_file):
    is_dvd = parse_mds_header(data)
    (sessions_offset,) = struct.unpack_from("<I", data, mds_sessions_offset)
    session_fields = mds_session_block.unpack_from(data, sessions_offset)
    num_all_blocks, tracks_offset = session_fields[3], session_fields[8]
    tracks = []
    for index in range(num_all_blocks):
        track = parse_mds_track(data, tracks_offset + index * mds_track_block.size, mds_file, is_dvd)
        if track:
            tracks.append(track)
    if not tracks:
        raise MdsError("no tracks")
    if is_dvd and len(tracks) > 1:
        raise MdsError("%d tracks on a dvd" % len(tracks))
    tracks.sort(key = lambda track: track["number"])
    return {"is_dvd": is_dvd, "tracks": tracks}

# Read a descriptor, or None when it cannot be converted
def read_mds_descriptor(mds_file, verbose = False, exit_on_failure = False):
    data = serialization.read_binary_file(mds_file, verbose = verbose, exit_on_failure = exit_on_failure)
    if data is None:
        logger.log_error("Unable to read %s" % mds_file)
        return None
    try:
        return parse_mds_descriptor(data, mds_file)
    except (MdsError, struct.error, IndexError, UnicodeDecodeError) as e:
        logger.log_error("Unable to convert %s: %s" % (mds_file, e))
        return None

# Get the data files a descriptor reads
def get_mds_data_files(descriptor):
    return sorted({track["data_file"] for track in descriptor["tracks"]})

# Check if chdman can read the data file as it is: one file holding the tracks
# back to back from its start, with no subchannel
def can_read_mdf_in_place(descriptor):
    tracks = descriptor["tracks"]
    if len(get_mds_data_files(descriptor)) != 1:
        return False
    expected_offset = 0
    for track in tracks:
        if track["subchannel_size"] or track["start_offset"] != expected_offset:
            return False
        expected_offset += track["length"] * track["sector_size"]
    return paths.get_file_size(tracks[0]["data_file"]) == expected_offset

# Format frames as cue time
def format_cue_time(frames):
    minutes, frames = divmod(frames, 60 * cd_frames_per_second)
    seconds, frames = divmod(frames, cd_frames_per_second)
    return "%02d:%02d:%02d" % (minutes, seconds, frames)

# Build a cue sheet from (file name, index frames) per track
def build_cue_sheet(descriptor, track_sources):
    lines = []
    current_file = None
    for position, (track, (file_name, index_frames)) in enumerate(zip(descriptor["tracks"], track_sources, strict = True)):
        if file_name != current_file:
            lines.append("FILE \"%s\" BINARY" % file_name)
            current_file = file_name
        lines.append("  TRACK %02d %s" % (track["number"], track["cue_type"]))
        pregap = track["pregap"]
        if position == 0:
            pregap -= standard_first_pregap
        if pregap > 0:
            lines.append("    PREGAP %s" % format_cue_time(pregap))
        lines.append("    INDEX 01 %s" % format_cue_time(index_frames))
    return "\n".join(lines) + "\n"

# Get track sources that read the data file in place, or None when its path cannot go in a cue
def get_in_place_track_sources(descriptor, cue_dir):
    relative_file = paths.get_relative_path(descriptor["tracks"][0]["data_file"], cue_dir)
    if relative_file is None or "\"" in relative_file:
        return None
    track_sources = []
    index_frames = 0
    for track in descriptor["tracks"]:
        track_sources.append((relative_file, index_frames))
        index_frames += track["length"]
    return track_sources

# Write a cue sheet for a descriptor into an empty directory
# The cue reads the data file in place when chdman can; otherwise each track is
# copied out beside the cue, without its subchannel
def write_mds_cue_sheet(
    descriptor,
    cue_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Read in place
    cue_dir = paths.get_filename_directory(cue_file)
    track_sources = None
    if can_read_mdf_in_place(descriptor):
        track_sources = get_in_place_track_sources(descriptor, cue_dir)

    # Copy tracks out
    if track_sources is None:
        track_sources = []
        for track in descriptor["tracks"]:
            track_name = "Track %02d.bin" % track["number"]
            success = serialization.copy_binary_records(
                src = track["data_file"],
                dest = paths.join_paths(cue_dir, track_name),
                offset = track["start_offset"],
                record_count = track["length"],
                record_size = track["sector_size"],
                keep_size = track["main_size"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Unable to copy track %d out of %s" % (track["number"], track["data_file"]))
                return False
            track_sources.append((track_name, 0))

    # Write cue
    return serialization.write_text_file(
        src = cue_file,
        contents = build_cue_sheet(descriptor, track_sources),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Convert an mds image to a cue sheet in an empty directory
# Returns (cue file, the mds and its data files), or None
def convert_mds_to_cue(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    descriptor = read_mds_descriptor(source_file, verbose = verbose, exit_on_failure = exit_on_failure)
    if not descriptor:
        return None
    cue_file = paths.join_paths(output_dir, paths.get_filename_basename(source_file) + config.DiscImageFileType.CUE.cval())
    success = write_mds_cue_sheet(
        descriptor = descriptor,
        cue_file = cue_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return None
    return (cue_file, [source_file] + get_mds_data_files(descriptor))
