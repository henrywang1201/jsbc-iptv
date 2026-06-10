#!/usr/bin/env python3
import argparse
import html
import os
import re
import unicodedata
from dataclasses import dataclass


ID_RE = r"C[0-9]{8}@JSBC"
BASE_URL = "rtsp://157.0.143.37:554/JSBC_iptv/{content_id}"
FALLBACK_CHANNELS = {
    "C10000026@JSBC": ("CCTV-少儿", 314),
    "C10000060@JSBC": ("江西卫视", 350),
    "C10000173@JSBC": ("CETV1HD", 176),
    "C10000235@JSBC": ("梨园HD", 381),
    "C10000426@JSBC": ("卡酷少儿HD", 108),
    "C10000435@JSBC": ("北京卫视4K(HDR)", 503),
    "C10000443@JSBC": ("江苏省城市足球联赛3", 408),
}


@dataclass
class Channel:
    content_id: str
    name: str
    number: int | None = None
    url: str | None = None


def clean_text(data: bytes) -> str:
    text = data.decode("utf-8", errors="ignore")
    text = text.replace("\x00", "")
    return html.unescape(text)


def clean_url(url: str) -> str:
    return url.rstrip("/,;'\"")


def number_or_none(value: str | None) -> int | None:
    if value and value.isdigit():
        return int(value)
    return None


def sanitize_name(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = "".join(ch for ch in value if unicodedata.category(ch)[0] != "C").strip()
    if not cleaned or len(cleaned) > 40:
        return None
    return cleaned


def name_quality(value: str) -> tuple[int, int]:
    bad = sum(1 for ch in value if unicodedata.category(ch)[0] == "C")
    return (bad, len(value))


def remember(channels: dict[str, Channel], content_id: str, name: str | None = None, number: int | None = None):
    name = sanitize_name(name)
    channel = channels.get(content_id)
    if not channel:
        channel = Channel(content_id=content_id, name=name or content_id)
        channels[content_id] = channel
    if name and (
        channel.name == content_id
        or name_quality(name) < name_quality(channel.name)
        or (name_quality(name) == name_quality(channel.name) and len(name) > len(channel.name))
    ):
        channel.name = name
    if number is not None and (channel.number is None or number < channel.number):
        channel.number = number
    channel.url = BASE_URL.format(content_id=content_id)


def extract_channels(text: str) -> dict[str, Channel]:
    channels: dict[str, Channel] = {}

    # EPG metadata JSON fragments.
    for match in re.finditer(
        rf'"name":"([^"]+)"\s*,\s*"contentId":"({ID_RE})".*?"thirdName":"?([0-9]+)"?',
        text,
        re.S,
    ):
        name, content_id, number = match.groups()
        remember(channels, content_id, name=name, number=number_or_none(number))

    for match in re.finditer(
        rf'"contentId":"({ID_RE})"[^{{}}]{{0,1400}}?"thirdName":("?)([0-9]+)\2'
        rf'[^{{}}]{{0,1400}}?"keyword":"([^"]+)"',
        text,
        re.S,
    ):
        content_id, _quote, number, name = match.groups()
        remember(channels, content_id, name=name, number=number_or_none(number))

    # Portal CU_CTC_Auther channel declarations.
    for match in re.finditer(
        rf'ChannelID="({ID_RE})",ChannelName="([^"]+)",UserChannelID="([0-9]+)"',
        text,
    ):
        content_id, name, number = match.groups()
        remember(channels, content_id, name=name, number=number_or_none(number))

    # Any remaining channel RTSP URLs not covered by metadata.
    for match in re.finditer(rf"rtsp://157\.0\.143\.37:554/JSBC_iptv/({ID_RE})", text):
        remember(channels, match.group(1))

    for content_id, (name, number) in FALLBACK_CHANNELS.items():
        if content_id in channels:
            remember(channels, content_id, name=name, number=number)

    return channels


def extract_live_sessions(text: str) -> list[str]:
    urls = []
    seen = set()
    for match in re.finditer(r"rtsp://157\.0\.143\.[0-9]+:[0-9]+/LIVE/[^\s\"<>]+", text):
        url = clean_url(match.group(0))
        if "TRANSPORT=MP2T/TCP" not in url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def m3u_escape(value: str) -> str:
    return value.replace('"', "'")


def write_channel_m3u(path: str, channels: dict[str, Channel]):
    rows = sorted(
        channels.values(),
        key=lambda c: (c.number is None, c.number if c.number is not None else 999999, c.name, c.content_id),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        for channel in rows:
            number = "" if channel.number is None else str(channel.number)
            name = m3u_escape(channel.name)
            f.write(
                f'#EXTINF:-1 tvg-id="{channel.content_id}" tvg-name="{name}" '
                f'tvg-chno="{number}" group-title="JSBC IPTV",{name}\n'
            )
            f.write("#EXTVLCOPT:rtsp-tcp\n")
            f.write((channel.url or BASE_URL.format(content_id=channel.content_id)) + "\n")
    return rows


def write_live_m3u(path: str, urls: list[str], channels: dict[str, Channel]):
    with open(path, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        for index, url in enumerate(urls, start=1):
            content_match = re.search(ID_RE, url)
            content_id = content_match.group(0) if content_match else f"LIVE-{index}"
            channel = channels.get(content_id)
            name = m3u_escape(channel.name if channel else content_id)
            f.write(
                f'#EXTINF:-1 tvg-id="{content_id}" tvg-name="{name}" '
                f'group-title="JSBC IPTV LIVE",{name} LIVE {index}\n'
            )
            f.write("#EXTVLCOPT:rtsp-tcp\n")
            f.write(url + "\n")


def main():
    parser = argparse.ArgumentParser(description="Extract JSBC RTSP IPTV M3U playlists from a pcapng file.")
    parser.add_argument("capture")
    parser.add_argument("--channels-out", default="jsbc_rtsp_0610.m3u")
    parser.add_argument("--live-out", default="jsbc_rtsp_live_sessions_0610.m3u")
    args = parser.parse_args()

    with open(args.capture, "rb") as f:
        text = clean_text(f.read())

    channels = extract_channels(text)
    live_urls = extract_live_sessions(text)
    rows = write_channel_m3u(args.channels_out, channels)
    write_live_m3u(args.live_out, live_urls, channels)

    print(f"channels={len(rows)} file={os.path.abspath(args.channels_out)}")
    print(f"live_sessions={len(live_urls)} file={os.path.abspath(args.live_out)}")
    for channel in rows[:20]:
        number = "" if channel.number is None else f"{channel.number:>3} "
        print(f"{number}{channel.name} {channel.url}")


if __name__ == "__main__":
    main()
