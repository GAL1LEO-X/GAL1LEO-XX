"""Persisted ordering fences in the existing metadata table.

Callers advance these counters inside their own IMMEDIATE transaction. Keeping
them in metadata requires no table migration and preserves existing archives.
"""


def counter(db, key):
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return int(row[0]) if row else 0


def advance(db, key):
    value = counter(db, key) + 1
    db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, str(value)))
    return value


def membership_key(ref):
    return "vehicle_membership_epoch:" + ref


def subscription_key(identifier):
    return "subscription_epoch:" + identifier
