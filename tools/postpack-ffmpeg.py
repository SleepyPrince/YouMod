#!/usr/bin/env python3
"""Append FFmpeg frameworks as resources AFTER cyan has injected tweaks.

This is intentionally not a Mach-O patcher. Sideloadly will re-sign the IPA.
"""
import argparse
from pathlib import Path
import zipfile

NAMES = ('ffmpegkit', 'libavcodec', 'libavdevice', 'libavfilter',
         'libavformat', 'libavutil', 'libswresample', 'libswscale')
PREFIX = 'Payload/YouTube.app/YouMod.bundle/'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('ipa', type=Path)
    p.add_argument('cache', type=Path, help='path to cached ffmpegkit directory')
    args = p.parse_args()
    entries = []
    for name in NAMES:
        folder = args.cache / f'{name}.framework'
        binary = folder / name
        if not binary.is_file():
            p.error(f'missing FFmpeg binary: {binary}')
        for path in folder.rglob('*'):
            if path.is_file():
                entries.append((path, PREFIX + path.relative_to(args.cache).as_posix()))
    with zipfile.ZipFile(args.ipa, 'a', allowZip64=True) as ipa:
        present = set(ipa.namelist())
        existing_ffmpeg = [n for n in present if n.startswith(PREFIX) and
                           any(n.startswith(PREFIX + x + '.framework/') for x in NAMES)]
        if existing_ffmpeg:
            p.error('FFmpeg frameworks were already inserted by cyan; refusing duplicate')
        for src, dest in entries:
            if dest in present:
                p.error(f'duplicate ZIP entry: {dest}')
            ipa.write(src, dest, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        print(f'Appended {len(entries)} FFmpeg resource files to YouMod.bundle')


if __name__ == '__main__':
    main()
