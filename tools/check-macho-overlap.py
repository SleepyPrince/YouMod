#!/usr/bin/env python3
"""Validate the IPA executable's Mach-O load commands against __TEXT,__text."""
import argparse
import struct
import zipfile


def check(data):
    if len(data) < 32:
        raise ValueError('truncated Mach-O')
    magic, = struct.unpack_from('<I', data)
    if magic != 0xfeedfacf:
        raise ValueError(f'unsupported Mach-O magic {magic:#x} (expected arm64 thin)')
    _, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from('<8I', data)
    end = 32 + sizeofcmds
    pos = 32
    text_offset = None
    injected_ffmpeg = []
    for i in range(ncmds):
        if pos + 8 > end or pos + 8 > len(data):
            raise ValueError(f'command {i} outside load-command table')
        cmd, size = struct.unpack_from('<II', data, pos)
        if size < 8 or size % 8 or pos + size > end or pos + size > len(data):
            raise ValueError(f'invalid load command {i} at {pos:#x}, size={size}')
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects, = struct.unpack_from('<I', data, pos + 64)
            if 72 + nsects * 80 > size:
                raise ValueError(f'truncated segment sections in command {i}')
            for j in range(nsects):
                s = pos + 72 + j * 80
                section = data[s:s+16].split(b'\0')[0]
                segment = data[s+16:s+32].split(b'\0')[0]
                if section == b'__text' and segment == b'__TEXT':
                    text_offset, = struct.unpack_from('<I', data, s + 48)
        if cmd in (0xc, 0x18, 0x80000018, 0x8000001f, 0x1f, 0x20, 0x80000023):
            nameoff, = struct.unpack_from('<I', data, pos + 8)
            if nameoff < size:
                name = data[pos+nameoff:pos+size].split(b'\0')[0].decode('utf-8', 'replace')
                if any('/' + x + '.framework/' in name for x in ('ffmpegkit', 'libavcodec', 'libavdevice', 'libavfilter', 'libavformat', 'libavutil', 'libswresample', 'libswscale')):
                    injected_ffmpeg.append(name)
        pos += size
    if pos != end:
        raise ValueError(f'load-command table mismatch {pos:#x} vs {end:#x}')
    if text_offset is None:
        raise ValueError('missing __TEXT,__text section')
    spare = text_offset - end
    print(f'ncmds={ncmds} sizeofcmds={sizeofcmds} end={end:#x} __text={text_offset:#x} spare={spare}')
    print(f'FFmpeg direct main-executable dependencies: {len(injected_ffmpeg)}')
    if spare < 0:
        raise ValueError(f'Mach-O header overlaps __text by {-spare} bytes')
    if injected_ffmpeg:
        raise ValueError('FFmpeg was injected directly into main executable; expected resource-only')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('ipa')
    args = p.parse_args()
    with zipfile.ZipFile(args.ipa) as z:
        payloads = [n for n in z.namelist() if n.startswith('Payload/') and n.endswith('.app/YouTube')]
        if len(payloads) != 1:
            p.error(f'Expected one YouTube executable, found {payloads}')
        check(z.read(payloads[0]))


if __name__ == '__main__':
    main()
