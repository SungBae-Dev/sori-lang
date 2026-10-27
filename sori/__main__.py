"""SORI 통합 CLI.

- v0.3 프로젝트(sori.toml + .sori 통합 문법): 새 컴파일러 → Typed IR v2 → Python Backend(IR 해석기)
- v0.1/B1 선언형 DSL 파일(첫 줄이 `app "..."`): B1 동작을 그대로 유지(하위 호환). `sori migrate` 로 변환 권장
- `build` 는 명세/배포 산출물을 만든다. 네이티브 바이너리를 만들지 않는다.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from . import __version__

LEGACY_NOTE = "참고: v0.1 선언형 DSL 파일이에요. 'sori migrate {src}' 로 통합 문법(v0.3)으로 옮길 수 있어요"


def _json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n'


def _is_legacy(path):
    from .framework.app import is_legacy_source
    p = Path(path)
    if p.is_file():
        try:
            return is_legacy_source(p.read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError):
            return False
    return False


# ---------------------------------------------------------------- v0.1/B1 경로 (원래 동작 유지)
def _legacy(cmd, a):
    from .compiler import SoriSyntaxError, manifest, parse_file
    from .openapi import openapi
    from .typed_ir import typed_ir
    try:
        program = parse_file(a.path)
        if cmd == 'check':
            print(f'OK: {program.name}, {len(program.routes)} routes, {len(program.workers)} workers')
        elif cmd == 'manifest':
            print(_json(manifest(program)), end='')
        elif cmd == 'ir':
            print(_json(typed_ir(program)), end='')
        elif cmd == 'openapi':
            print(_json(openapi(program)), end='')
        elif cmd == 'build':
            if getattr(a, 'target', 'spec') != 'spec':
                print('v0.1 DSL 은 --target spec 만 지원해요. OCI 배포는 sori migrate 후 사용하세요', file=sys.stderr)
                return 2
            out = Path(a.out)
            out.mkdir(parents=True, exist_ok=True)
            artifacts = {'manifest.json': manifest(program), 'typed-ir.json': typed_ir(program),
                         'openapi.json': openapi(program)}
            for name, value in artifacts.items():
                (out / name).write_text(_json(value), encoding='utf-8')
            print(f'Wrote {len(artifacts)} JSON artifacts to {out} (no native binary generated)')
        elif cmd in ('serve', 'dev', 'run'):
            try:
                import uvicorn
            except ImportError:
                print('Install server dependency: pip install -e ".[server]"', file=sys.stderr)
                return 2
            from .runtime import create_app
            uvicorn.run(create_app(program), host=a.host or '127.0.0.1', port=a.port or 8000,
                        proxy_headers=False, server_header=False, limit_concurrency=100, timeout_keep_alive=5)
        else:
            print(f"'{cmd}' 는 v0.1 DSL 에서 지원하지 않아요. 'sori migrate {a.path}' 후 사용하세요", file=sys.stderr)
            return 2
        print(LEGACY_NOTE.format(src=a.path), file=sys.stderr)
    except (SoriSyntaxError, ValueError, OSError) as exc:
        print(f'SORI error: {exc}', file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------- v0.3 경로
def _load(path, quiet=False, json_out=False):
    from .framework.app import build_app
    from .lang.diagnostics import render_all
    app, diags = build_app(path)
    if app.legacy_files:
        from .lang.diagnostics import SoriError
        for f in app.legacy_files:
            app.project.diags.insert(0, SoriError("E002", "v0.1 선언형 DSL 파일은 통합 프로젝트에 섞을 수 없어요", f, 1, 1,
                                                  f"'sori migrate {os.path.join(app.root, f)}' 로 변환하세요"))
        diags = app.project.diags
    errs = [d for d in diags if d.severity == 'error']
    if diags and not quiet:
        print(render_all(diags, app.sources, json_out), file=sys.stdout if json_out else sys.stderr)
    return app, errs


def cmd_check(a):
    if _is_legacy(a.path):
        return _legacy('check', a)
    app, errs = _load(a.path, json_out=a.json)
    if a.json and not app.project.diags:
        print('[]')
    if not a.json:
        warns = len([d for d in app.project.diags if d.severity == 'warning'])
        print(f"{'✗' if errs else '✓'} {len(app.sources)}개 파일 · 오류 {len(errs)} · 경고 {warns} · 라우트 {len(app.ir['routes'])}"
              f" · IR {app.ir['ir_version']}", file=sys.stderr)
    return 1 if errs else 0


def _spec_cmd(kind):
    def run(a):
        if _is_legacy(a.path):
            return _legacy(kind, a)
        app, errs = _load(a.path, quiet=True)
        if errs:
            _load(a.path)
            return 1
        from .tools import deploy
        from .tools.openapi_v2 import openapi
        value = {'ir': lambda: app.ir, 'openapi': lambda: openapi(app.ir, app.config),
                 'manifest': lambda: deploy.manifest(app), 'tools': lambda: deploy.tools(app)}[kind]()
        print(deploy.canonical_json(value), end='')
        return 0
    return run


def cmd_build(a):
    if _is_legacy(a.path):
        return _legacy('build', a)
    app, errs = _load(a.path)
    if errs:
        return 1
    from .tools import deploy
    if a.target == 'spec':
        names = deploy.build_spec(app, a.out)
        print(f'Wrote {len(names)} JSON artifacts to {a.out} ({", ".join(names)}; no native binary generated)')
        return 0
    out = deploy.build_oci(app, None if a.out == '.sori-build' else a.out)
    print(f'✓ sori.lock 생성 (해시 {len(app.lock_digest())}개)')
    print(f'✓ OCI 빌드 컨텍스트: {out} (이미지는 직접 빌드: docker build -t {app.name}:latest {out})')
    return 0


def cmd_run(a, dev=False):
    if _is_legacy(a.path):
        return _legacy('dev' if dev else 'run', a)
    if dev:
        os.environ.setdefault('SORI_ENV', 'development')
    app, errs = _load(a.path)
    if errs:
        print(f'✗ 오류 {len(errs)}개 — 실행하지 않았어요', file=sys.stderr)
        return 1
    has_routes = any(True for _ in app.ir['routes'])
    server = None
    if has_routes:
        server = 'builtin' if dev and not a.server else (a.server or app.config.get('app', {}).get('server', 'uvicorn'))
    problems = app.startup_problems('serve', server=server)
    if problems:
        for p in problems:
            print(f'✗ 기동 거부: {p}', file=sys.stderr)
        return 3
    app.load()
    from .framework.web import serve
    if app.router.routes:
        port = a.port or int(os.environ.get('PORT', app.config.get('app', {}).get('port', 8080)))
        host = a.host or ('0.0.0.0' if app.env == 'production' else '127.0.0.1')
        if server == 'uvicorn':
            from .framework.asgi import serve_uvicorn
            serve_uvicorn(app, host, port)
        else:
            serve(app, host, port)  # 내장 서버: 개발 전용 (운영에서는 위 startup_problems 가 거부)
    elif app.tasks:
        runners = app.start_tasks()
        print(f'▶ 주기 작업 {len(runners)}개 실행 중 (Ctrl+C 로 종료)', file=sys.stderr)
        try:
            end = time.time() + a.duration if a.duration else None
            while end is None or time.time() < end:
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        for r in runners:
            r.stop.set()
        print(app.metrics.text(), file=sys.stderr)
    return 0


def cmd_test(a):
    # B1 호환: --start-directory 를 주거나, 대상에 .sori 가 없으면 unittest discovery
    target = a.path or '.'
    has_sori = Path(target).is_file() or (Path(target).is_dir() and (any(Path(target).glob('*.sori')) or
                                                                       (Path(target) / 'sori.toml').exists()))
    if a.start_directory or a.unittest or not has_sori:
        start = a.start_directory or 'tests'
        # 신뢰하지 않는 소스를 subprocess 로 넘기지 않는다 — 고정 인자만
        return subprocess.call([sys.executable, '-m', 'unittest', 'discover', '-s', start, '-v'])
    if _is_legacy(target):
        print("v0.1 DSL 파일에는 test 블록이 없어요. 'sori test --start-directory tests' 를 쓰세요", file=sys.stderr)
        return 2
    app, errs = _load(target)
    if errs:
        return 1
    app.access_log = False
    problems = app.startup_problems('test')
    if problems:
        for p in problems:
            print(f'✗ {p}', file=sys.stderr)
        return 3
    app.load()
    ok = fail = 0
    for name, fn, file, line in app.tests:
        t0 = time.perf_counter()
        try:
            fn()
            ok += 1
            print(f'  ✓ {name}  ({(time.perf_counter() - t0) * 1000:.1f}ms)')
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                raise
            fail += 1
            code, msg, where = app.describe(e)
            print(f'  ✗ {name}  [{file}:{line}]\n      → {where}: {msg}')
    print(f"\n{'✓' if not fail else '✗'} 통과 {ok} · 실패 {fail}")
    return 1 if fail else 0


def cmd_gen(kind):
    def run(a):
        if _is_legacy(a.path):
            return _legacy(kind, a)
        app, errs = _load(a.path, quiet=True)
        if errs:
            _load(a.path)
            return 1
        from .tools import deploy
        if kind == 'k8s':
            text = deploy.k8s(app, a.image, a.replicas, a.egress)
            if app.perms.get('net') and a.egress == 'none':
                print('⚠ net 권한이 있지만 표준 NetworkPolicy 로는 도메인 단위 허용이 안 돼서 외부 이그레스를 막았어요. '
                      'Cilium 이면 --egress cilium, 아니면 egress gateway 를 쓰세요', file=sys.stderr)
            print(text)
        elif kind == 'compose':
            print(deploy.compose(app, a.image))
        elif kind == 'audit':
            print(deploy.audit(app))
        elif kind == 'context':
            text = deploy.context(app)
            if a.write:
                Path(app.root, 'SORI_CONTEXT.md').write_text(text, encoding='utf-8')
                print('✓ SORI_CONTEXT.md 작성', file=sys.stderr)
            else:
                print(text)
        return 0
    return run


def cmd_new(a):
    from .tools.deploy import new_project
    try:
        new_project(a.target)
    except (FileExistsError, OSError) as e:
        print(f'SORI error: {e}', file=sys.stderr)
        return 1
    print(f'Created SORI project at {a.target} (sori.toml + app.sori)\n  sori test {a.target} && sori dev {a.target}')
    return 0


def cmd_migrate(a):
    from .tools.migrate import MigrationError, migrate_file
    out = a.out or str(Path(a.path).with_suffix('')) + '-v0.3'
    try:
        files, report = migrate_file(a.path, out, a.force)
    except (MigrationError, OSError) as e:
        print(f'SORI error: {e}', file=sys.stderr)
        return 1
    except Exception as e:  # 원본이 v0.1 문법이 아니거나 잘못된 경우
        print(f'SORI error: v0.1 소스를 읽지 못했어요: {e}', file=sys.stderr)
        return 1
    for line in report:
        print(line)
    print(f'✓ {out}/ 에 {", ".join(sorted(files))} 작성 — 다음: sori check {out}')
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='sori', description=f'SORI {__version__} — 보안 기본값 + AI 네이티브 언어/프레임워크')
    p.add_argument('--version', action='version', version=f'sori {__version__}')
    sub = p.add_subparsers(dest='command', required=True)

    def add(name, fn, help_, path=True, default='.'):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        if path:
            sp.add_argument('path', nargs='?', default=default, help='프로젝트 폴더 또는 .sori 파일')
        return sp

    sp = add('check', cmd_check, '정적 검사 (--json: AI 용 진단)')
    sp.add_argument('--json', action='store_true')
    for name in ('ir', 'openapi', 'manifest', 'tools'):
        add(name, _spec_cmd(name), {'ir': 'Typed IR (v0.3 프로젝트: sori/ir/v2, v0.1 파일: v1)', 'openapi': 'OpenAPI 3.1',
                                    'manifest': '라우트/권한 요약', 'tools': 'AI 에이전트 툴 스키마'}[name])
    sp = add('build', cmd_build, '산출물 생성: --target spec(기본, JSON 명세) | oci(Docker 컨텍스트 + sori.lock)')
    sp.add_argument('--target', choices=['spec', 'oci'], default='spec')
    sp.add_argument('--out', default='.sori-build', help='출력 폴더 (spec 기본 .sori-build, oci 기본 <프로젝트>/.sori/build)')
    for name, dev in (('run', False), ('dev', True), ('serve', False)):
        sp = add(name, (lambda d: lambda a: cmd_run(a, d))(dev),
                 {'run': '실행 (서버: sori.toml [app] server, 기본 uvicorn)', 'dev': '개발 실행 (내장 서버, 상세 오류)',
                  'serve': 'run 별칭 (B1 호환)'}[name])
        sp.add_argument('--host')
        sp.add_argument('--port', type=int)
        sp.add_argument('--server', choices=['builtin', 'uvicorn'])
        sp.add_argument('--duration', type=float, help='task 전용 실행 시간(초)')
    sp = add('test', cmd_test, '.sori test 블록 실행 (--start-directory / --unittest: unittest discovery, B1 호환)', default=None)
    sp.add_argument('--start-directory')
    sp.add_argument('--unittest', action='store_true')
    sp = add('context', cmd_gen('context'), 'AI 코딩 도우미용 프로젝트 컨텍스트')
    sp.add_argument('--write', action='store_true')
    add('audit', cmd_gen('audit'), '보안 감사 보고서 (권한·효과·접근 정책·검증되지 않은 영역)')
    sp = add('k8s', cmd_gen('k8s'), 'Kubernetes 매니페스트 (권한 → NetworkPolicy, 워커 사이드카)')
    sp.add_argument('--image')
    sp.add_argument('--replicas', type=int, default=2)
    sp.add_argument('--egress', choices=('none', 'cilium'), default='none',
                    help='외부 이그레스: none(기본, DNS 만) | cilium(CiliumNetworkPolicy toFQDNs 로 net 권한만)')
    sp = add('compose', cmd_gen('compose'), 'Docker Compose (앱 + 워커 사이드카)')
    sp.add_argument('--image')
    sp = add('new', cmd_new, '새 프로젝트 (sori.toml + app.sori)', path=False)
    sp.add_argument('target')
    sp = add('migrate', cmd_migrate, 'v0.1 선언형 DSL → 통합 문법(v0.3) 변환', path=False)
    sp.add_argument('path')
    sp.add_argument('--out')
    sp.add_argument('--force', action='store_true')
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == '__main__':
    raise SystemExit(main())
