# Story channels
story_channels = [
    { "name": "Being Scared", "url": "https://www.youtube.com/channel/UCrggft5vtcVpzLVCfQ0FBhg" },
    { "name": "Blue_Spooky", "url": "https://www.youtube.com/@BlueSpooky/videos" },
    { "name": "Corpse Husband", "url": "https://www.youtube.com/@CorpseHusband/videos" },
    { "name": "Doctor Horror", "url": "https://www.youtube.com/@DoctorHorror/videos" },
    { "name": "Midnight Bard", "url": "https://www.youtube.com/channel/UCNz16DszwHW1HLi5g7-WVpg" },
    { "name": "Mr Nightmare", "url": "https://www.youtube.com/@mrnightmare/videos" },
    { "name": "Mr. Haunted", "url": "https://www.youtube.com/channel/UCS_BR42yv9YAx0XFy1tKXZg/videos" },
    { "name": "Mr. Night Scares", "url": "https://www.youtube.com/@Mr.Nightscares/videos" },
    { "name": "Mr.Spooky", "url": "https://www.youtube.com/@MrSpookyStories/videos" },
    { "name": "Night Time Spooks", "url": "https://www.youtube.com/@nighttimespooks/videos" },
    { "name": "Phantom Librarian", "url": "https://rumble.com/c/c-2666954" },
    { "name": "Ripshy", "url": "https://www.youtube.com/@heyshyily" },
    { "name": "Scarystuff Ding", "url": "https://www.youtube.com/@scarystuffscarystuffscarys3780/videos" },
    { "name": "Southern Cannibal", "url": "https://www.youtube.com/@SouthernCannibal/videos" },
    { "name": "Stop and Scare!", "url": "https://www.youtube.com/@StopandScare-/videos" },
    { "name": "Unit 522", "url": "https://www.youtube.com/@UNIT522/videos" },
    { "name": "Whispered Diaries", "url": "https://www.youtube.com/@whispereddiaries/videos" }
]

# ASMR channels
asmr_channels = [
    { "name": "Gentle Whispering ASMR", "url": "https://www.youtube.com/@GentleWhisperingASMR/videos" }
]

# Number of videos to download, archive, and upload per batch (incremental, so a
# channel's audio is uploaded in chunks instead of all at the end). 0 = no batching.
audio_download_batch_size = 25

# Number of fragments to download concurrently per video (yt-dlp -N). Speeds up
# individual downloads without running multiple videos in parallel. The download
# layer clamps this to a safe maximum (see google.MAX_CONCURRENT_FRAGMENTS) to
# avoid triggering YouTube rate limits / bans. 1 = no concurrency (sequential).
audio_download_concurrent_fragments = 4

# Download a channel's videos oldest-first instead of the default newest-first.
# Channels enumerate newest-first; enabling this reverses the (new, not-yet-
# archived) video list before batching, so batch 1 is the oldest videos. The
# download_audio_files --oldest_first flag also enables it per-run.
audio_download_oldest_first = False

# Genres whose tracks should be renumbered by file index when tagging. These are
# downloaded from YouTube (via download_audio_files), where yt-dlp embeds bogus,
# uniform track numbers; every other genre keeps its existing track numbers. Used
# by tag_audio_files to decide the --use_index_for_track_number policy per genre.
# Values must match AudioGenreType members.
audio_track_index_genres = ["ASMR", "Story"]
