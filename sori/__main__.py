from __future__ import annotations

import argparse
import json
import sys
from .compiler import SoriSyntaxError, manifest, parse_file
from .runtime import create_app


def main() -> int:
    parser = argparse.ArgumentParser(prog='sori', description='SORI v0.1 language tool')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('check', 'manifest', 'serve'):
        sub = commands.add_parser(name)
        sub.add_argument('source', help='path to .sori file')
        if name == 'serve':
            sub.add_argument('--host', default='127.0.0.1')
            sub.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    try:
        program = parse_file(args.source)
        if args.command == 'check':
            print(f'OK: {program.name}, {len(program.routes)} routes, {len(program.workers)} workers')
        elif args.command == 'manifest':
            print(json.dumps(manifest(program), ensure_ascii=False, indent=2))
        elif args.command == 'serve':
            try:
                import uvicorn
            except ImportError:
                print('Install server dependency: pip install -e ".[server]"', file=sys.stderr)
                return 2
            app = create_app(program)
            uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False,
                        server_header=False, limit_concurrency=100, timeout_keep_alive=5)
    except (SoriSyntaxError, ValueError, OSError) as exc:
        print(f'SORI error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
