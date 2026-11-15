"""Generate nonpersonal media for an explicitly requested local QA run."""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import wave
import zlib


def generate_media(destination, ffmpeg):
    destination, ffmpeg = Path(destination), Path(ffmpeg)
    if not ffmpeg.is_file():
        raise ValueError('Supply an existing ffmpeg executable')
    destination.mkdir(parents=True, exist_ok=False)
    width, height = 640, 360
    colors = [(230, 50, 50), (50, 200, 90), (40, 110, 230), (240, 200, 40)]
    rows = []
    for y in range(height):
        row = bytearray(b'\x00')
        for x in range(width):
            color = colors[min(3, x * 4 // width)]
            row.extend(color if (x // 40 + y // 40) % 2 == 0 else tuple(c // 2 for c in color))
        rows.append(bytes(row))
    def chunk(kind, payload):
        return (struct.pack('!I', len(payload)) + kind + payload
                + struct.pack('!I', zlib.crc32(kind + payload) & 0xffffffff))
    png = (b'\x89PNG\r\n\x1a\n'
           + chunk(b'IHDR', struct.pack('!2I5B', width, height, 8, 2, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(b''.join(rows))) + chunk(b'IEND', b''))
    (destination / 'QA-colors.png').write_bytes(png)
    with wave.open(str(destination / 'QA-tones.wav'), 'wb') as stream:
        stream.setparams((1, 2, 24000, 0, 'NONE', 'not compressed'))
        stream.writeframes(b''.join(struct.pack('<h', int(5000 * math.sin(
            2 * math.pi * (440 if i < 24000 else 660) * i / 24000))) for i in range(57600)))
    common = [str(ffmpeg.resolve()), '-hide_banner', '-loglevel', 'error', '-n']
    subprocess.run(common + ['-f', 'lavfi', '-i', 'testsrc2=size=640x360:rate=24',
        '-f', 'lavfi', '-i', 'sine=frequency=880:sample_rate=44100', '-t', '3',
        '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-movflags', '+faststart',
        str(destination / 'QA-motion.mp4')], check=True, timeout=60)
    subprocess.run(common + ['-i', str(destination / 'QA-colors.png'), '-vf', 'scale=512:512',
        '-c:v', 'libwebp', '-frames:v', '1', str(destination / 'QA-sticker.webp')],
        check=True, timeout=60)
    (destination / 'QA-document.txt').write_text(
        'QA generated-media\nGenerated test document, no personal data.\n'
        'Characters: à è ì ò ù 😀\n', encoding='utf-8')
    fixtures = [{'name': path.name, 'size': path.stat().st_size,
                 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in sorted(destination.iterdir()) if path.is_file()]
    result = {'fixtures': fixtures, 'width': width, 'height': height,
              'video_seconds': 3, 'audio_seconds': 2.4, 'live_calls': 0}
    (destination / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result

