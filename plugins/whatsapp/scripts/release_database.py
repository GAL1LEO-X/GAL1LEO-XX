"""Declarative SQLite migrations, tested against a copy before any live change."""
import ast
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time

from github_release_common import require


def literal(path, name):
    for node in ast.parse(Path(path).read_text(encoding='utf-8-sig')).body:
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == name for x in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('Missing declaration: '+name)


def validate(db):
    require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'SQLite integrity check failed')
    require(not db.execute('PRAGMA foreign_key_check').fetchall(), 'SQLite foreign key check failed')


def snapshot(source, destination):
    source, destination = Path(source), Path(destination)
    require(source.is_file() and not source.is_symlink(), 'Unexpected database file')
    require(not destination.exists(), 'Database snapshot already exists')
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True)) as src, closing(sqlite3.connect(destination)) as dst:
        src.backup(dst)
        dst.execute('PRAGMA journal_mode=DELETE')
        validate(dst)
    destination.chmod(0o600)


def quote(name):
    return '"'+name.replace('"', '""')+'"'


def tables(db):
    return [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND substr(lower(name),1,7) != 'sqlite_' ORDER BY name")]


def identities(db):
    result = {}
    # FTS maintenance can legitimately rebuild its internal index rows while
    # application record IDs remain unchanged. SQLite identifies shadow tables;
    # do not infer them from names that could also belong to user tables.
    shadows = {row[1] for row in db.execute('PRAGMA table_list')
               if row[0] == 'main' and row[2] == 'shadow'}
    for table in tables(db):
        if table in shadows:
            continue
        columns = db.execute('PRAGMA table_info('+quote(table)+')').fetchall()
        keys = [r[1] for r in sorted(columns, key=lambda r:r[5]) if r[5]]
        if not keys:
            continue
        names = ','.join(map(quote, keys))
        digest, count = hashlib.sha256(), 0
        for row in db.execute('SELECT '+names+' FROM '+quote(table)+' ORDER BY '+names):
            digest.update(repr(row).encode('utf-8')); digest.update(b'\n'); count += 1
        result[table] = (keys, count, digest.hexdigest())
    return result


def contract(source):
    source = Path(source)
    value = json.loads((source/'deploy/migrations.json').read_text())
    require(type(value.get('schemaVersion')) is int and value['schemaVersion'] >= 6, 'Invalid migration schema version')
    require(isinstance(value.get('migrations'), list), 'Migration list is missing')
    previous = set()
    for step in value['migrations']:
        require(set(step) == {'from', 'to', 'sql'}, 'Invalid migration fields')
        require(type(step['from']) is int and step['to'] == step['from']+1 and step['from'] not in previous,
                'Migrations must be unique, consecutive version steps')
        previous.add(step['from'])
        path = (source/'deploy'/step['sql']).resolve()
        require(path.is_relative_to((source/'deploy').resolve()) and path.is_file() and not path.is_symlink(),
                'Migration SQL must be inside the release deploy directory')
    return value


def execute_script(db, sql):
    deadline = time.monotonic()+30
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    def authorize(action, first, second, database, trigger):
        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and str(second).lower() == 'load_extension':
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA and second is not None and str(first).lower() != 'user_version':
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_CREATE_VTABLE and str(second).lower() != 'fts5':
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_TRANSACTION:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    # Execute complete statements ourselves: executescript implicitly commits.
    db.execute('BEGIN IMMEDIATE')
    db.set_authorizer(authorize)
    try:
        statement = ''
        for char in sql:
            statement += char
            if char == ';' and sqlite3.complete_statement(statement):
                db.execute(statement); statement = ''
        if statement.strip():
            db.execute(statement)
        db.set_authorizer(None)
        db.commit()
    except BaseException:
        db.set_authorizer(None); db.rollback(); raise
    finally:
        db.set_progress_handler(None, 0)


def ascii_fold(value):
    return value.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))


def declaration(sql, kind, name):
    """Conservative DDL fingerprint, retaining every expression and constraint.

    SQLite preserves cosmetic differences after ALTER TABLE. Ignore whitespace,
    comments, keyword case, IF NOT EXISTS, and quoting of declared object/column
    names only. Do not unquote expression tokens: SQLite double-quoted strings
    can be literals, so treating them as identifiers can hide a changed CHECK.
    Other equivalent spellings deliberately fail closed for explicit review.
    """
    tokens = []
    pattern = re.compile(
        '\\s+|--[^\\n]*(?:\\n|$)|/\\*.*?\\*/|\'(?:[^\']|\'\')*\'|\\"(?:[^\\"]|\\"\\")*\\"|`(?:[^`]|``)*`|\\[[^\\]]*\\]|[A-Za-z_\\x80-\\uffff][\\w$]*|0[xX][0-9A-Fa-f]+|(?:\\d+(?:\\.\\d*)?|\\.\\d+)(?:[eE][+-]?\\d+)?|->>|->|\\|\\||<<|>>|<=|>=|==|!=|<>|.', re.DOTALL)
    for match in pattern.finditer(sql):
        value = match.group()
        if value.isspace() or value.startswith(('--', '/*')):
            continue
        if value[0] == "'":
            tokens.append(('string', value))
        elif value[0] in ('"', '`', '['):
            tokens.append(('quoted', value))
        elif re.match(r'[A-Za-z_\x80-\uffff]', value):
            tokens.append(('word', ascii_fold(value)))
        else:
            tokens.append(('symbol', value))
    while tokens and tokens[-1] == ('symbol', ';'):
        tokens.pop()
    position = next(index for index, token in enumerate(tokens) if token == ('word', kind)) + 1
    if tokens[position:position+3] == [('word', 'if'), ('word', 'not'), ('word', 'exists')]:
        del tokens[position:position+3]

    def identifier(index):
        category, value = tokens[index]
        if category == 'quoted':
            value = value[1:-1].replace(value[0]*2, value[0]) if value[0] != '[' else value[1:-1]
        require(category in ('quoted', 'word', 'string'), 'Unexpected schema identifier')
        # Single-quoted names are accepted by SQLite in declarations only.
        if category == 'string':
            value = value[1:-1].replace("''", "'")
        tokens[index] = ('identifier', ascii_fold(value))

    identifier(position)
    require(tokens[position][1] == ascii_fold(name), 'Schema object name differs from its declaration')
    if kind == 'table' and tokens[position+1:position+2] == [('symbol', '(')]:
        depth, start = 0, True
        constraints = {'constraint', 'primary', 'unique', 'check', 'foreign'}
        for index in range(position+2, len(tokens)):
            token = tokens[index]
            if start:
                if token[0] != 'word' or token[1] not in constraints:
                    identifier(index)
                start = False
            if token == ('symbol', '('): depth += 1
            elif token == ('symbol', ')'):
                if depth == 0: break
                depth -= 1
            elif token == ('symbol', ',') and depth == 0: start = True
    return tokens


def schema(db):
    result = {}
    for table in tables(db):
        indexes = []
        for row in db.execute('PRAGMA index_list('+quote(table)+')'):
            columns = [(entry[0], entry[1], entry[2], entry[3], ascii_fold(entry[4]), entry[5])
                       for entry in db.execute('PRAGMA index_xinfo('+quote(row[1])+')')]
            indexes.append((row[1], row[2], row[3], row[4], columns))
        result[table] = {'columns': db.execute('PRAGMA table_xinfo('+quote(table)+')').fetchall(),
                         'foreignKeys': db.execute('PRAGMA foreign_key_list('+quote(table)+')').fetchall(),
                         'indexes': sorted(indexes)}
    definitions = {}
    for kind, name, table, sql in db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE substr(lower(name),1,7) != 'sqlite_' ORDER BY type,name"):
        require(sql is not None, 'Unexpected schema object without a declaration')
        definitions[(kind, name, table)] = declaration(sql, kind, name)
    return {'tables': result, 'declarations': definitions}


def migrate(database, source):
    spec = contract(source)
    with closing(sqlite3.connect(database)) as db, closing(sqlite3.connect(':memory:')) as expected:
        validate(db)
        before = identities(db)
        version = initial = db.execute('PRAGMA user_version').fetchone()[0]
        require(6 <= version <= spec['schemaVersion'], 'Database schema is unsupported or newer than the release')
        steps = {step['from']:step for step in spec['migrations']}
        while version < spec['schemaVersion']:
            require(version in steps, 'A required database migration is missing')
            step = steps[version]
            execute_script(db, (Path(source)/'deploy'/step['sql']).read_text())
            require(db.execute('PRAGMA user_version').fetchone()[0] == step['to'], 'Migration did not set its declared schema version')
            version = step['to']
        execute_script(expected, literal(Path(source)/'sally_whatsapp/store.py', 'SCHEMA'))
        require(expected.execute('PRAGMA user_version').fetchone()[0] == spec['schemaVersion'], 'Store schema and migration declaration disagree')
        require(schema(db) == schema(expected), 'Migrated schema does not match the candidate application')
        after = identities(db)
        require(all(after.get(name) == value for name, value in before.items()), 'Migration removed or changed existing record identities')
        validate(db)
        db.execute('PRAGMA journal_mode=DELETE')
        return {'fromSchema': initial, 'toSchema': version, 'integrity': 'ok', 'recordIdentitiesPreserved': True}
