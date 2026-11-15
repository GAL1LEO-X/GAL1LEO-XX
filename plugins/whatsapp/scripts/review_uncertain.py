#!/usr/bin/env python3
"""Prepare/apply an explicit historical-review plan; never operate on WhatsApp.

Preparing opens SQLite read-only. Applying modifies only private review/audit
metadata in the exact database, with the exact reviewed plan digest. No migration,
service action, ledger rewrite, reconciliation of outcomes or automatic retry.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sally_whatsapp import uncertain_review as review


def read_json(path):
    if path.stat().st_size > 256 * 1024:
        raise ValueError('Review input exceeds size bound')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate input field')
            value[key] = item
        return value
    return json.loads(path.read_text(), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite input')))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--owner', required=True)
    prepare.add_argument('--keys', type=Path, required=True, help='Private JSON array of complete idempotency keys')
    prepare.add_argument('--mode', choices=sorted(review.MODES), default='acknowledge_known_history')
    prepare.add_argument('--evidence-ref', help='SHA256 of the reviewed diagnostic report, without contents')
    prepare.add_argument('--output', type=Path, required=True)
    apply = commands.add_parser('apply')
    apply.add_argument('--plan', type=Path, required=True)
    apply.add_argument('--plan-sha256', required=True, help='Digest printed by prepare; explicitly reviewed')
    args = parser.parse_args(argv)
    path = args.database.resolve(strict=True)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('One existing regular database is required')
    db = sqlite3.connect(path.as_uri() + ('?mode=ro' if args.command == 'prepare' else '?mode=rw'), uri=True)
    db.row_factory = sqlite3.Row
    try:
        with db:
            if args.command == 'prepare':
                db.execute('PRAGMA query_only=ON')
                plan = review.prepare(db,args.owner,read_json(args.keys),mode=args.mode,evidence_ref=args.evidence_ref)
                fd = os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as stream:
                    stream.write(review.encoded(plan)+'\n')
                result = {'state':'prepared','plan_sha256':review.digest(plan),'count':len(plan['cases']),
                          'database_changes':db.total_changes,'outcomes_changed':False}
            else:
                result = review.apply(db,read_json(args.plan),args.plan_sha256)
        print(json.dumps(result,sort_keys=True))
    finally:
        db.close()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, RecursionError):
        print(json.dumps({'error':'REVIEW_REJECTED','detail':'Verify the exact plan, current evidence, owner and database.'}))
        raise SystemExit(2)
