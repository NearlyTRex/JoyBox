# Imports
import re

# Local imports
import joybox.logger as logger
import joybox.command as command
import joybox.programs as programs

# Browser user agent. Rumble fingerprint-blocks some HTTP clients (python
# requests gets a 403); curl with a browser user agent is served normally.
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# Rumble channel/user landing pages, e.g.
#   https://rumble.com/c/c-2666954
#   https://rumble.com/c/ChannelName
#   https://rumble.com/user/SomeUser
RUMBLE_CHANNEL_REGEX = re.compile(r"^https?://(www\.)?rumble\.com/(c|user)/[^/?#]+/?$", re.IGNORECASE)

# A Rumble video url as embedded in the channel page's JSON, e.g.
#   "url":"https://rumble.com/v2fyso2-true-paranormal-experiences-volume-i.html"
# yt-dlp's RumbleChannel extractor no longer parses the current channel markup
# (it scrapes 0 items), so we enumerate the videos from this embedded JSON and
# hand the individual video urls to yt-dlp, whose single-video extractor works.
VIDEO_URL_REGEX = re.compile(r'"url":"(https://rumble\.com/(v[a-z0-9]+)-[a-z0-9-]*\.html)"', re.IGNORECASE)

# Safety cap on channel pages to fetch (Rumble lists ~25 videos per page, and
# returns a 404 body past the last page). Guards against an infinite loop if the
# stop condition never trips.
MAX_CHANNEL_PAGES = 200

# Check if a url is a Rumble channel/user page
def is_rumble_channel_url(url):
    return bool(url) and bool(RUMBLE_CHANNEL_REGEX.match(url.strip()))

# Fetch a channel page's html via curl. Rumble blocks python requests, so we use
# curl (which the network layer already relies on) with a browser user agent.
def fetch_channel_page(page_url, verbose = False, pretend_run = False, exit_on_failure = False):

    # Get tool
    curl_tool = None
    if programs.is_tool_installed("Curl"):
        curl_tool = programs.get_tool_program("Curl")
    if not curl_tool:
        logger.log_error("Curl was not found")
        return None

    # Fetch (silent, follow redirects, browser user agent)
    fetch_cmd = [curl_tool, "-s", "-L", "-A", USER_AGENT, page_url]
    return command.run_output_command(
        cmd = fetch_cmd,
        options = command.create_command_options(blocking_processes = [curl_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Enumerate a Rumble channel's videos as (id, url) pairs, paging until a page
# yields no new videos (the last page + 1 returns a 404 body with no video json).
# The id is Rumble's url-slug id; it is not yt-dlp's canonical archive id, so the
# download layer relies on yt-dlp's own --download-archive to skip existing
# videos rather than the pre-download filter.
def get_channel_video_urls(channel_url, verbose = False, pretend_run = False, exit_on_failure = False):

    # Normalize to the base channel url (strip any query/trailing slash)
    base_url = channel_url.strip().split("?", 1)[0].rstrip("/")

    # Page through the channel
    videos = []
    seen = set()
    for page in range(1, MAX_CHANNEL_PAGES + 1):
        page_url = f"{base_url}?page={page}"
        html = fetch_channel_page(
            page_url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not html:
            break

        # Extract unique videos from the embedded page json
        page_new = 0
        for match in VIDEO_URL_REGEX.finditer(html):
            video_url = match.group(1)
            video_id = match.group(2)
            if video_id not in seen:
                seen.add(video_id)
                videos.append((video_id, video_url))
                page_new += 1

        # Stop once a page adds nothing new (end of the channel)
        if page_new == 0:
            break
    if verbose:
        logger.log_info(f"Enumerated {len(videos)} videos from Rumble channel: {base_url}")
    return videos
