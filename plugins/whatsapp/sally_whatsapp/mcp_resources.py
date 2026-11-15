"""Bounded MCP reads of existing signed attachments, never arbitrary URI fetches."""
import base64
import hashlib
import os
import re

from mcp import types


# Larger files retain the existing streamed HTTPS download. Base64 and JSON
# overhead are bounded too; no 512 MiB attachment is materialized in a response.
MAX_RESOURCE_BYTES = 1024 * 1024


def read_verified_attachment(media, uri, owner):
    """Return bounded original bytes after the same checks for every consumer."""
    prefix = media.settings.public_url + '/files/'
    if not isinstance(uri, str) or not uri.startswith(prefix):
        raise ValueError('Resource unavailable')
    grant = uri[len(prefix):]
    if not re.fullmatch(r'[A-Za-z0-9_=-]{1,4096}', grant):
        raise ValueError('Resource unavailable')
    _, row = media.resolve(grant, owner=owner, maximum=MAX_RESOURCE_BYTES)
    descriptor = media._verify_cache(row, keep_open=True)
    with os.fdopen(descriptor, 'rb') as stream:
        data = stream.read(MAX_RESOURCE_BYTES + 1)
    if (len(data) != row['size'] or len(data) > MAX_RESOURCE_BYTES
            or hashlib.sha256(data).hexdigest() != row['sha256']):
        raise ValueError('Resource unavailable')
    # Revalidate grant, owner, visibility, source and lifetime after reading.
    # Returning only the bytes just hashed avoids path replacement races.
    _, current = media.resolve(grant, owner=owner, maximum=MAX_RESOURCE_BYTES)
    if (current['sha256'] != row['sha256'] or current['size'] != row['size']
            or current['mimetype'] != row['mimetype']):
        raise ValueError('Resource unavailable')
    return data, current['mimetype']


def read_attachment(media, uri, owner):
    data, mimetype = read_verified_attachment(media, uri, owner)
    return types.ReadResourceResult(contents=[types.BlobResourceContents(
        uri=uri, mime_type=mimetype, blob=base64.b64encode(data).decode('ascii'))])
