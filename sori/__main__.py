"""sori CLI — run / check / test / emit / build / k8s / context / tools / audit / new"""
import argparse
import json
import os
import sys
import threading
import time

from . import __version__
from .diagnostics import render_all


def _load(path, quiet=False, json_out=False):
    from .runtime.app import build_app
    app, diags = build_app(path)
    errs = [d for d in diags if d.severity == "error"]
    if diags and not quiet:
        print(render_all(diags, app.sources, json_out), file=sys.stderr if not json_out else sys.stdout)
    return app, errs


def cmd_check(a):
    app, errs = _load(a.path, json_out=a.json)
    if a.json and not app.project.diags:
        print("[]")
    if not a.json:
        n_warn = len([d for d in app.project.diags if d.severity == "warning"])
        files = len(app.sources)
        print(f"{'✗' if errs else '✓'} {files}개 파일 · 오류 {len(errs)} · 경고 {n_warn} · 라우트 {len(app.project.routes)}", file=sys.stderr)
    return 1 if errs else 0


def cmd_emit(a):
    app, errs = _load(a.path)
    print(app.pysrc)
    return 1 if errs else 0


def cmd_run(a):
    app, errs = _load(a.path)
    if errs:
        print(f"✗ 오류 {len(errs)}개 — 실행하지 않았어요", file=sys.stderr)
        return 1
    problems = app.startup_problems("serve")
    if problems:
        for p in problems:
            print(f"✗ 기동 거부: {p}", file=sys.stderr)
        return 3
    app.load()
    from .runtime.web import serve
    if app.router.routes:
        port = a.port or int(os.environ.get("PORT", app.config.get("app", {}).get("port", 8080)))
        host = a.host or ("0.0.0.0" if app.env == "production" else "127.0.0.1")
        server = a.server or app.config.get("app", {}).get("server", "builtin")
        if server == "uvicorn":
            from .runtime.asgi import serve_uvicorn
            serve_uvicorn(app, host, port)
        else:
            serve(app, host, port)
    elif app.tasks:
        runners = app.start_tasks()
        print(f"▶ 주기 작업 {len(runners)}개 실행 중 (Ctrl+C 로 종료)", file=sys.stderr)
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
    app, errs = _load(a.path)
    if errs:
        return 1
    app.access_log = False
    problems = app.startup_problems("test")
    if problems:
        for p in problems:
            print(f"✗ {p}", file=sys.stderr)
        return 3
    app.load()
    from .runtime.core import ExpectFailed
    ok = fail = 0
    for name, fn, file, line in app.tests:
        t0 = time.perf_counter()
        try:
            fn()
            ok += 1
            print(f"  ✓ {name}  ({(time.perf_counter() - t0) * 1000:.1f}ms)")
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                raise
            fail += 1
            code, msg, where = app.describe(e)
            print(f"  ✗ {name}  [{file}:{line}]\n      → {where}: {msg}")
    print(f"\n{'✓' if not fail else '✗'} 통과 {ok} · 실패 {fail}")
    return 1 if fail else 0


def cmd_build(a):
    app, errs = _load(a.path)
    if errs:
        return 1
    from .deploy import build
    out = build(app)
    print(f"✓ sori.lock 생성 (소스 해시 {len(app.sources)}개)")
    print(f"✓ 빌드 컨텍스트: {out}")
    print(f"  docker build -t {app.config.get('app', {}).get('name', 'sori-app')}:latest {out}")
    return 0


def cmd_k8s(a):
    app, errs = _load(a.path, quiet=True)
    if errs:
        return 1
    from .deploy import k8s
    print(k8s(app, a.image, a.replicas))
    return 0


def cmd_compose(a):
    app, errs = _load(a.path, quiet=True)
    if errs:
        return 1
    from .deploy import compose
    print(compose(app, a.image))
    return 0


def cmd_context(a):
    app, errs = _load(a.path, quiet=True)
    from .deploy import context
    text = context(app)
    if a.write:
        with open(os.path.join(app.root, "SORI_CONTEXT.md"), "w", encoding="utf-8") as f:
            f.write(text)
        print("✓ SORI_CONTEXT.md 작성", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_tools(a):
    app, errs = _load(a.path, quiet=True)
    from .deploy import tools
    print(json.dumps(tools(app), ensure_ascii=False, indent=2))
    return 0


def cmd_audit(a):
    app, errs = _load(a.path, quiet=True)
    from .deploy import audit
    print(audit(app))
    return 1 if errs else 0


def cmd_new(a):
    from .deploy import new_project
    new_project(a.name)
    print(f"✓ {a.name}/ 생성\n  cd {a.name} && sori test && sori run")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="sori", description="SORI — 보안 기본값 + AI 네이티브 언어/프레임워크")
    p.add_argument("--version", action="version", version=f"sori {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        return sp

    sp = add("run", cmd_run, "앱 실행 (라우트가 있으면 서버, task 만 있으면 제어 루프)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int)
    sp.add_argument("--duration", type=float, help="task 전용 실행 시간(초)")
    sp.add_argument("--server", choices=["builtin", "uvicorn"], help="HTTP 서버 (기본: sori.toml [app] server, 없으면 builtin)")
    sp = add("check", cmd_check, "정적 검사 (사람용 / --json 은 AI 용)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--json", action="store_true")
    for name, fn, h in [("test", cmd_test, "test 블록 실행"), ("emit", cmd_emit, "생성된 파이썬 코드 보기"),
                        ("build", cmd_build, "sori.lock + Docker 빌드 컨텍스트 생성"), ("tools", cmd_tools, "AI 에이전트용 툴 스키마(JSON)"),
                        ("audit", cmd_audit, "보안 감사 보고서")]:
        add(name, fn, h).add_argument("path", nargs="?", default=".")
    sp = add("context", cmd_context, "AI 코딩 도우미용 프로젝트 컨텍스트")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--write", action="store_true", help="SORI_CONTEXT.md 로 저장")
    sp = add("k8s", cmd_k8s, "Kubernetes 매니페스트 (권한 → NetworkPolicy)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--image")
    sp.add_argument("--replicas", type=int, default=2)
    sp = add("compose", cmd_compose, "Docker Compose (앱 + 워커 사이드카)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--image")
    sp = add("new", cmd_new, "새 프로젝트 만들기")
    sp.add_argument("name")
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
