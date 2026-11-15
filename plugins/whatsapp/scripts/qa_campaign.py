#!/usr/bin/env python3
"""Prepare/run offline contracts and inspect a local resumable QA campaign.

No credentials, HTTP requests, WhatsApp operations or browser sessions are
created by this CLI. Native tools and the controlled browser are external
executors; the journal records their exact, separately obtained evidence.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    contracts = sub.add_parser('contracts')
    contracts.add_argument('--output', type=Path, required=True)
    contracts.add_argument('--surface', action='append')
    build = sub.add_parser('build')
    build.add_argument('--output', type=Path, required=True)
    media = sub.add_parser('media-fixtures')
    media.add_argument('--output', type=Path, required=True)
    media.add_argument('--ffmpeg', type=Path, required=True, help='Existing trusted ffmpeg executable')
    suites = sub.add_parser('suites')
    suites.add_argument('--run', action='append', help='Explicit synthetic suite selection; omit to list only')
    suites.add_argument('--output', type=Path, help='A new results directory, required with --run')
    init = sub.add_parser('init')
    init.add_argument('--journal', type=Path, required=True)
    init.add_argument('--manifest', type=Path)
    init.add_argument('--bindings', type=Path)
    init.add_argument('--run-id')
    for name in ('next', 'record', 'report', 'bind', 'enable-live'):
        command = sub.add_parser(name)
        command.add_argument('--journal', type=Path, required=True)
        if name == 'record':
            command.add_argument('--step', required=True)
            command.add_argument('--result', type=Path, required=True)
        if name == 'report':
            command.add_argument('--output', type=Path)
        if name == 'bind':
            command.add_argument('--name', required=True)
            command.add_argument('--value-file', type=Path, required=True)
        if name == 'enable-live':
            command.add_argument('--authorization', required=True)
    args = parser.parse_args(argv)
    if args.command == 'media-fixtures':
        from qa.media_fixtures import generate_media
        print(json.dumps(generate_media(args.output, args.ffmpeg), indent=2))
        return 0
    if args.command == 'contracts':
        from qa.schema_cases import run_contracts
        result = run_contracts(args.output, selected=args.surface)
        print(json.dumps({k: result[k] for k in ('counts', 'field_paths', 'live_calls')}, indent=2))
        return bool(result['counts'].get('FAIL'))
    if args.command == 'build':
        from qa.recipes import coverage_index
        from qa.suites import prepare_fixtures, suite_plan
        rows = coverage_index(Path(__file__).resolve().parents[1], args.output)
        root = Path(__file__).resolve().parents[1]
        fixtures = prepare_fixtures(root, args.output / 'synthetic-media')
        (args.output / 'synthetic-suites.json').write_text(json.dumps(suite_plan(root), indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'operations': len(rows), 'media_fixtures': len(fixtures['fixtures']), 'live_calls': 0}))
        return 0
    if args.command == 'suites':
        from qa.suites import run_suites, suite_plan
        root = Path(__file__).resolve().parents[1]
        if args.run:
            if not args.output:
                parser.error('--output is required when running suites')
            result = run_suites(root, args.run, args.output)
            print(json.dumps(result, indent=2))
            return result['exit_code']
        print(json.dumps(suite_plan(root), indent=2))
        return 0
    from qa.campaign import Journal
    if args.command == 'init':
        from qa.recipes import smoke_manifest
        manifest = json.loads(args.manifest.read_text(encoding='utf-8')) if args.manifest else smoke_manifest()
        bindings = json.loads(args.bindings.read_text(encoding='utf-8')) if args.bindings else {}
        journal = Journal.create(args.journal, manifest, bindings, run_id=args.run_id)
        result = journal.report()
    else:
        journal = Journal(args.journal)
        if args.command == 'next':
            result = journal.next()
        elif args.command == 'record':
            result = journal.record(args.step, json.loads(args.result.read_text(encoding='utf-8')))
        elif args.command == 'bind':
            journal.bind(args.name, json.loads(args.value_file.read_text(encoding='utf-8')))
            result = {'binding_registered': args.name}
        elif args.command == 'enable-live':
            journal.enable_live(args.authorization)
            result = {'live_enabled': True}
        else:
            result = journal.report()
    journal.close()
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if getattr(args, 'output', None):
        args.output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
