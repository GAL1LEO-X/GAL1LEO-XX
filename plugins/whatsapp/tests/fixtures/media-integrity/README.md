# Synthetic media integrity fixtures

These files contain only generated test material. `sample.txt` contains one
synthetic Unicode line; the PDF is a one-page empty document with an actual xref
table; the DOCX is a ZIP/OOXML package with content types, relationships and one
paragraph. The raster images are 16 × 16 solid-color samples. The audio is a
0.2-second 500 Hz generated tone (mono, 48 kHz). The MP4 contains a 16 × 16 blue
frame sequence plus the synthetic tone.

The PNG was constructed from PNG chunks with CRCs. ffmpeg converted it to JPEG
and WebP, generated PCM WAV and Ogg/Opus, and encoded H.264/AAC MP4. ffprobe
verified the listed media streams; `manifest.json` records exact byte sizes,
SHA256 digests and those observations. No account, recording, screenshot or user
document is included. Runtime code does not require ffmpeg to execute these
fixtures; the tests use the stored bytes and fake network boundaries.

Tests prove wrapper/transfer byte and metadata contracts with valid fixtures.
They do not certify live WhatsApp delivery or the provider's transcoder.
