"""Deliver bounded original images in tools/call, without a second resource RPC.

Container/header checks bound dimensions and reject unsupported/animated input;
they do not decode pixels or certify that a client can render the image.
"""
import base64
import hashlib
import zlib

from mcp import types

from .mcp_resources import MAX_RESOURCE_BYTES, read_verified_attachment


IMAGE_MIMES = frozenset(('image/jpeg', 'image/png', 'image/webp'))
MAX_IMAGE_PIXELS = 16_000_000
MAX_IMAGE_DIMENSION = 8192


def _png(data):
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return None
    offset, dimensions, image_data = 8, None, False
    while offset + 12 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], 'big')
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + size
        if end > len(data):
            return None
        payload = data[offset + 8:end - 4]
        checksum = int.from_bytes(data[end - 4:end], 'big')
        if zlib.crc32(kind + payload) & 0xffffffff != checksum:
            return None
        if offset == 8:
            if kind != b'IHDR' or size != 13:
                return None
            dimensions = (int.from_bytes(payload[:4], 'big'), int.from_bytes(payload[4:8], 'big'))
            depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
            if (payload[8] not in depths.get(payload[9], set())
                    or payload[10:12] != b'\0\0' or payload[12] not in {0, 1}):
                return None
        elif kind in {b'IHDR', b'acTL', b'fcTL', b'fdAT'}:
            return None
        if kind == b'IDAT':
            image_data = image_data or bool(size)
        if kind == b'IEND':
            return dimensions if size == 0 and end == len(data) and image_data else None
        offset = end
    return None


def _jpeg(data):
    if not data.startswith(b'\xff\xd8') or not data.endswith(b'\xff\xd9'):
        return None
    offset, dimensions = 2, None
    while offset + 4 <= len(data):
        if data[offset] != 0xff:
            return None
        while offset < len(data) and data[offset] == 0xff:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in {0, 0xd8, 0xd9} or 0xd0 <= marker <= 0xd7:
            return None
        size = int.from_bytes(data[offset:offset + 2], 'big')
        end = offset + size
        if size < 2 or end > len(data) - 2:
            return None
        payload = data[offset + 2:end]
        if marker in {0xc0, 0xc1, 0xc2}:
            if (dimensions is not None or len(payload) < 6 or payload[0] != 8
                    or payload[5] not in {1, 3, 4} or len(payload) != 6 + 3 * payload[5]):
                return None
            dimensions = (int.from_bytes(payload[3:5], 'big'), int.from_bytes(payload[1:3], 'big'))
        elif marker == 0xda:
            if len(payload) < 4 or len(payload) != 4 + 2 * payload[0] or end >= len(data) - 2:
                return None
            return dimensions
        elif marker in {0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf}:
            return None
        offset = end
    return None


def _webp(data):
    if (len(data) < 20 or data[:4] != b'RIFF' or data[8:12] != b'WEBP'
            or int.from_bytes(data[4:8], 'little') + 8 != len(data)):
        return None
    offset, canvas, frame = 12, None, None
    while offset + 8 <= len(data):
        kind = data[offset:offset + 4]
        size = int.from_bytes(data[offset + 4:offset + 8], 'little')
        end = offset + 8 + size
        if end + size % 2 > len(data):
            return None
        payload = data[offset + 8:end]
        if kind in {b'ANIM', b'ANMF'}:
            return None
        if kind == b'VP8X':
            if offset != 12 or size != 10 or payload[0] & 0xc3 or payload[1:4] != b'\0\0\0':
                return None
            canvas = (1 + int.from_bytes(payload[4:7], 'little'), 1 + int.from_bytes(payload[7:10], 'little'))
        elif kind in {b'VP8 ', b'VP8L'}:
            if frame is not None:
                return None
            if kind == b'VP8 ':
                if size < 10 or payload[0] & 1 or payload[3:6] != b'\x9d\x01\x2a':
                    return None
                frame = (int.from_bytes(payload[6:8], 'little') & 0x3fff,
                         int.from_bytes(payload[8:10], 'little') & 0x3fff)
            else:
                if size < 5 or payload[0] != 0x2f:
                    return None
                bits = int.from_bytes(payload[1:5], 'little')
                if bits >> 29:
                    return None
                frame = (1 + (bits & 0x3fff), 1 + ((bits >> 14) & 0x3fff))
        offset = end + size % 2
    if offset != len(data) or (canvas is not None and canvas != frame):
        return None
    return frame


def image_dimensions(data, mimetype):
    """Finite format admission only; no decompression or MIME guessing."""
    parser = {'image/jpeg': _jpeg, 'image/png': _png, 'image/webp': _webp}.get(mimetype)
    dimensions = parser(data) if parser else None
    if dimensions:
        width, height = dimensions
        if (0 < width <= MAX_IMAGE_DIMENSION and 0 < height <= MAX_IMAGE_DIMENSION
                and width * height <= MAX_IMAGE_PIXELS):
            return dimensions
    return None


def attachment_image(media, status, owner):
    """Return a real MCP image block, or explain the bounded fallback.

    A source/auth/integrity failure propagates: never return stale ready metadata
    or use an alternative copy. Unsupported formats retain the ordinary download.
    """
    info = {'included': False, 'max_bytes': MAX_RESOURCE_BYTES,
            'client_rendering_verified': False}
    if status.get('state') != 'ready':
        return {**info, 'reason': 'not_ready'}, None
    mimetype = status.get('mimetype')
    if mimetype not in IMAGE_MIMES:
        return {**info, 'reason': 'unsupported_mimetype'}, None
    size = status.get('size')
    if type(size) is not int or not 0 < size <= MAX_RESOURCE_BYTES:
        return {**info, 'reason': 'size_limit'}, None
    data, verified_mimetype = read_verified_attachment(media, status['download_url'], owner)
    if (verified_mimetype != mimetype or len(data) != size
            or hashlib.sha256(data).hexdigest() != status['sha256']):
        raise ValueError('Attachment changed before image delivery')
    dimensions = image_dimensions(data, mimetype)
    if dimensions is None:
        return {**info, 'reason': 'unsupported_or_invalid_image'}, None
    width, height = dimensions
    image = types.ImageContent(type='image', mime_type=mimetype,
                              data=base64.b64encode(data).decode('ascii'))
    return {**info, 'included': True, 'transport': 'mcp_image_content',
            'width': width, 'height': height}, image
