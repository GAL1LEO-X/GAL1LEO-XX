"""Real SQLite migration copies; no production services or credentials."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import release_database as database
from github_release_common import ReleaseError


@pytest.fixture
def migration(tmp_path):
    source=tmp_path/'source';(source/'deploy').mkdir(parents=True);(source/'sally_whatsapp').mkdir()
    schema='CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT);PRAGMA user_version=6;'
    live=tmp_path/'live.sqlite'
    with closing(sqlite3.connect(live)) as db:
        db.executescript(schema);db.execute("INSERT INTO messages VALUES('one','preserve')");db.commit()
    (source/'sally_whatsapp/store.py').write_text('SCHEMA='+repr('CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT,extra TEXT);PRAGMA user_version=7;'))
    (source/'deploy/migrations.json').write_text(json.dumps({'schemaVersion':7,'migrations':[{'from':6,'to':7,'sql':'6-7.sql'}]}))
    (source/'deploy/6-7.sql').write_text('ALTER TABLE messages ADD COLUMN extra TEXT;PRAGMA user_version=7;')
    copy=tmp_path/'copy.sqlite';database.snapshot(live,copy)
    return source,live,copy


def test_additive_migration_preserves_live_and_message(migration):
    source,live,copy=migration;original=live.read_bytes()
    assert database.migrate(copy,source)['toSchema']==7
    assert live.read_bytes()==original
    with closing(sqlite3.connect(copy)) as db:
        assert db.execute('SELECT id,body,extra FROM messages').fetchall()==[('one','preserve',None)]


def test_failed_migration_is_transactional_and_never_changes_live(migration):
    source,live,copy=migration;original=live.read_bytes()
    (source/'deploy/6-7.sql').write_text('ALTER TABLE messages ADD COLUMN extra TEXT;THIS IS INVALID;PRAGMA user_version=7;')
    with pytest.raises(sqlite3.Error):database.migrate(copy,source)
    assert live.read_bytes()==original
    with closing(sqlite3.connect(copy)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==6
        assert len(db.execute('PRAGMA table_info(messages)').fetchall())==2


def test_lost_record_rejected(migration):
    source,live,copy=migration
    path=source/'deploy/6-7.sql';path.write_text(path.read_text()+"DELETE FROM messages;")
    with pytest.raises(ReleaseError,match='record identities'):database.migrate(copy,source)


@pytest.mark.parametrize('sql',['ATTACH DATABASE "/tmp/escape" AS escape;','PRAGMA journal_mode=OFF;','COMMIT;','SELECT load_extension("escape");'])
def test_sql_cannot_escape_transaction_or_database(migration,sql):
    source,live,copy=migration
    (source/'deploy/6-7.sql').write_text(sql)
    with pytest.raises(sqlite3.Error):database.migrate(copy,source)


def test_missing_step_fails_closed(migration):
    source,live,copy=migration
    (source/'deploy/migrations.json').write_text(json.dumps({'schemaVersion':7,'migrations':[]}))
    with pytest.raises(ReleaseError,match='missing'):database.migrate(copy,source)


def test_current_schema_matches_real_store(tmp_path):
    from sally_whatsapp.store import Store
    live=tmp_path/'current.sqlite';Store(live,recover_inflight=False)
    source = Path(__file__).resolve().parents[1]
    result=database.migrate(live,source)
    assert result['fromSchema']==result['toSchema']==database.contract(source)['schemaVersion']


def test_real_schema_missing_check_fails_before_publication(tmp_path):
    from sally_whatsapp.store import SCHEMA
    live = tmp_path/'missing-check.sqlite'
    with closing(sqlite3.connect(live)) as db:
        db.executescript(SCHEMA.replace('CHECK(singleton=1)', ''))
    with pytest.raises(ReleaseError, match='schema does not match'):
        database.migrate(live, Path(__file__).resolve().parents[1])


def test_migration_with_unexpected_trigger_fails_before_publication(migration):
    source, live, copy = migration
    original = live.read_bytes()
    script = source/'deploy/6-7.sql'
    script.write_text(script.read_text()+"CREATE TRIGGER unexpected AFTER INSERT ON messages "
                      "BEGIN UPDATE messages SET body='changed' WHERE id=new.id; END;")
    with pytest.raises(ReleaseError, match='schema does not match'):
        database.migrate(copy, source)
    assert live.read_bytes() == original


def fingerprint(sql):
    with closing(sqlite3.connect(':memory:')) as db:
        db.executescript(sql)
        return database.schema(db)


@pytest.mark.parametrize(('expected', 'changed'), [
    ('CREATE TABLE t(id INTEGER PRIMARY KEY CHECK(id=1));',
     'CREATE TABLE t(id INTEGER PRIMARY KEY);'),
    ('CREATE TABLE t(id INTEGER,body TEXT CHECK(body=\'Case\'));',
     'CREATE TABLE t(id INTEGER,body TEXT CHECK(body=\'case\'));'),
    # Double quotes may be SQLite string literals. Unquoting everything would
    # hide this difference (the string "true" is false in a CHECK).
    ('CREATE TABLE t(id INTEGER CHECK(true));',
     'CREATE TABLE t(id INTEGER CHECK("true"));'),
    ('CREATE TABLE t(id INTEGER,body TEXT);CREATE INDEX idx ON t(lower(body));',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE INDEX idx ON t(upper(body));'),
    ('CREATE TABLE t(id INTEGER,body TEXT);CREATE INDEX idx ON t(id) WHERE id>0;',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE INDEX idx ON t(id) WHERE id<0;'),
    ('CREATE TABLE t(id INTEGER,body TEXT);CREATE INDEX idx ON t(body COLLATE NOCASE DESC);',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE INDEX idx ON t(body COLLATE BINARY ASC);'),
    ('CREATE TABLE t(id INTEGER,body TEXT);CREATE VIEW v AS SELECT body FROM t;',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE VIEW v AS SELECT id FROM t;'),
    ('CREATE TABLE t(id INTEGER,body TEXT);',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE VIEW v AS SELECT id FROM t;'),
    ('CREATE TABLE t(id INTEGER,body TEXT);',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE TABLE sqliteXextra(id INTEGER PRIMARY KEY);'),
    ('CREATE TABLE t(id INTEGER,body TEXT);',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE TRIGGER sqliteXextra AFTER INSERT ON t '
     'BEGIN UPDATE t SET body=\'changed\' WHERE id=new.id; END;'),
    ('CREATE VIRTUAL TABLE search USING fts5(body,tokenize=\'unicode61\');',
     'CREATE VIRTUAL TABLE search USING fts5(body,tokenize=\'porter\');'),
    ('CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT,body TEXT);',
     'CREATE TABLE t(id INTEGER PRIMARY KEY,body TEXT);'),
    ('CREATE TABLE t(id INTEGER,body TEXT);CREATE TRIGGER changed AFTER INSERT ON t '
     'BEGIN UPDATE t SET body=\'correct\' WHERE id=new.id; END;',
     'CREATE TABLE t(id INTEGER,body TEXT);CREATE TRIGGER changed AFTER INSERT ON t '
     'BEGIN UPDATE t SET body=\'different\' WHERE id=new.id; END;'),
])
def test_schema_comparison_rejects_semantic_drift(expected, changed):
    assert fingerprint(expected) != fingerprint(changed)


def test_schema_comparison_accepts_add_column_and_cosmetic_declarations():
    expected = 'CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,body TEXT,extra TEXT CHECK(length(extra)<8));'
    altered = '''create table "messages"(
        `id` text PRIMARY KEY, /* harmless comment */ [body] TEXT
    );
    ALTER TABLE messages ADD COLUMN "extra" TEXT CHECK(length(extra)<8);'''
    assert fingerprint(expected) == fingerprint(altered)


def test_schema_comparison_accepts_builtin_collation_name_case():
    expected = 'CREATE TABLE t(body TEXT);CREATE INDEX idx ON t(body COLLATE NOCASE DESC);'
    assert fingerprint(expected) == fingerprint(expected.replace('NOCASE', 'nocase'))


def test_fts_cleanup_preserves_application_identities_during_migration(tmp_path):
    source = tmp_path/'source'
    (source/'deploy').mkdir(parents=True)
    (source/'sally_whatsapp').mkdir()
    schema = ('CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT);'
              "CREATE VIRTUAL TABLE message_search USING fts5(id UNINDEXED,body,tokenize='unicode61');")
    (source/'sally_whatsapp/store.py').write_text('SCHEMA='+repr(schema+'PRAGMA user_version=7;'))
    (source/'deploy/migrations.json').write_text(json.dumps({'schemaVersion': 7,
        'migrations': [{'from': 6, 'to': 7, 'sql': '6-7.sql'}]}))
    (source/'deploy/6-7.sql').write_text("UPDATE messages SET body='' WHERE id='revoked';"
                                      "DELETE FROM message_search WHERE id='revoked';PRAGMA user_version=7;")
    copy = tmp_path/'copy.sqlite'
    with closing(sqlite3.connect(copy)) as db:
        db.executescript(schema+"PRAGMA user_version=6;INSERT INTO messages VALUES('revoked','private');"
                         "INSERT INTO message_search VALUES('revoked','private');")
    assert database.migrate(copy, source)['recordIdentitiesPreserved']
    with closing(sqlite3.connect(copy)) as db:
        assert db.execute('SELECT * FROM messages').fetchall() == [('revoked', '')]
        assert not db.execute('SELECT * FROM message_search').fetchall()


def test_sqlitex_prefix_does_not_hide_application_record_loss(migration):
    source, live, copy = migration
    with closing(sqlite3.connect(copy)) as db:
        db.executescript("CREATE TABLE sqliteXextra(id TEXT PRIMARY KEY);INSERT INTO sqliteXextra VALUES('preserve');")
    expected = source/'sally_whatsapp/store.py'
    schema = database.literal(expected, 'SCHEMA') + 'CREATE TABLE sqliteXextra(id TEXT PRIMARY KEY);'
    expected.write_text('SCHEMA='+repr(schema))
    script = source/'deploy/6-7.sql'
    script.write_text(script.read_text()+'DELETE FROM sqliteXextra;')
    with pytest.raises(ReleaseError, match='record identities'):
        database.migrate(copy, source)
