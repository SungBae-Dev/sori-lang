"""SORI developer CLI. `build` exports specs, it does not compile a native binary."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from .compiler import SoriSyntaxError, manifest, parse_file
from .openapi import openapi
from .typed_ir import typed_ir


def _json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n'


def _new(target: str) -> None:
    path = Path(target)
    if path.exists():
        raise ValueError('target already exists (refusing to overwrite)')
    path.mkdir(parents=True)
    (path / 'app.sori').write_text('''app "My SORI API"
route GET "/health" public:
  return {"status": "ok"}
route POST "/greet" protected:
  input name: str(1, 80)
  return {"message": "Hello, " + input.name}
''', encoding='utf-8')
    (path / '.gitignore').write_text('.sori-build/\n.env\n__pycache__/\n', encoding='utf-8')
    (path / 'README.md').write_text('# My SORI API\n\nRun `sori check app.sori` before deployment.\n', encoding='utf-8')
    print(f'Created SORI project at {path}')


def main() -> int:
    parser = argparse.ArgumentParser(prog='sori', description='SORI 0.2-alpha developer tools')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('check', 'manifest', 'serve', 'dev', 'ir', 'openapi', 'build'):
        sub = commands.add_parser(name)
        sub.add_argument('source', help='path to .sori source')
        if name in ('serve', 'dev'):
            sub.add_argument('--host', default='127.0.0.1')
            sub.add_argument('--port', type=int, default=8000)
        if name == 'build':
            sub.add_argument('--out', default='.sori-build', help='artifact output directory')
    new = commands.add_parser('new', help='scaffold a minimal project')
    new.add_argument('target', help='new project folder')
    test = commands.add_parser('test', help='run unittest discovery')
    test.add_argument('--start-directory', default='tests')
    args = parser.parse_args()
    try:
        if args.command == 'new':
            _new(args.target)
            return 0
        if args.command == 'test':
            # Do not pass untrusted SORI source into subprocess; constant argv only.
            return subprocess.call([sys.executable, '-m', 'unittest', 'discover',
                                    '-s', args.start_directory, '-v'])
        program = parse_file(args.source)
        if args.command == 'check':
            print(f'OK: {program.name}, {len(program.routes)} routes, {len(program.workers)} workers')
        elif args.command == 'manifest':
            print(_json(manifest(program)), end='')
        elif args.command == 'ir':
            print(_json(typed_ir(program)), end='')
        elif args.command == 'openapi':
            print(_json(openapi(program)), end='')
        elif args.command == 'build':
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            artifacts = {'manifest.json': manifest(program), 'typed-ir.json': typed_ir(program),
                         'openapi.json': openapi(program)}
            for name, value in artifacts.items():
                (out / name).write_text(_json(value), encoding='utf-8')
            print(f'Wrote {len(artifacts)} JSON artifacts to {out} (no native binary generated)')
        elif args.command in ('serve', 'dev'):
            try:
                import uvicorn
            except ImportError:
                print('Install server dependency: pip install -e " .[server]"', file=sys.stderr)
                return 2
            from .runtime import create_app
            uvicorn.run(create_app(program), host=args.host, port=args.port,
                        proxy_headers=False, server_header=False,
                        limit_concurrency=100, timeout_keep_alive=5)
    except (SoriSyntaxError, ValueError, OSError) as exc:
        print(f'SORI error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())