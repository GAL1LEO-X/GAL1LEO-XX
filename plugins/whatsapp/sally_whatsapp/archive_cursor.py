"""Signed archive cursors: stable insertion cutoff, current content and revocations."""
import base64
import hashlib
import hmac
import json
import secrets
import time


def cursor_key(store):
    key_name='private:archive_cursor_key'
    with store.db() as db:
        row=db.execute('SELECT value FROM state WHERE key=?',(key_name,)).fetchone()
    if not row:
        with store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR IGNORE INTO state VALUES(?,?)',(key_name,json.dumps(secrets.token_hex(32))))
            row=db.execute('SELECT value FROM state WHERE key=?',(key_name,)).fetchone()
    return bytes.fromhex(json.loads(row[0]))


def query_identity(query,chat_id,after,before,chat_type='all'):
    # Keep existing unfiltered cursors usable; typed searches have a distinct
    # identity and cannot cross into another category on a subsequent page.
    filters=[query,chat_id,after,before]
    if chat_type!='all': filters.append({'chat_type':chat_type})
    data=json.dumps(filters,ensure_ascii=False,separators=(',',':'))
    return hashlib.sha256(data.encode()).hexdigest()


def encode_cursor(key,query,cutoff,boundary,expires):
    data=json.dumps({'v':1,'query':query,'cutoff':cutoff,'boundary':boundary,'expires':expires},separators=(',',':')).encode()
    body=base64.urlsafe_b64encode(data).decode().rstrip('=')
    return body+'.'+hmac.digest(key,body.encode(),'sha256').hex()


def decode_cursor(key,cursor,query):
    try:
        if not isinstance(cursor,str) or len(cursor)>2048: raise ValueError()
        body,signature=cursor.split('.')
        if not hmac.compare_digest(hmac.digest(key,body.encode(),'sha256').hex(),signature): raise ValueError()
        value=json.loads(base64.b64decode(body+'='*(-len(body)%4),altchars=b'-_',validate=True))
        if value['v']!=1 or value['query']!=query or type(value['cutoff']) is not int or value['cutoff']<0: raise ValueError()
        if type(value['expires']) is not int or value['expires']<=time.time(): raise ValueError()
        boundary=value['boundary']
        if not isinstance(boundary,list) or len(boundary)!=2 or type(boundary[0]) is not int or not isinstance(boundary[1],str): raise ValueError()
        return value
    except (ValueError,TypeError,KeyError,UnicodeError):
        raise ValueError('Invalid, expired or incompatible archive cursor; restart the search') from None
