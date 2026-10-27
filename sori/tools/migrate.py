"""SORI v0.1/B1 선언형 DSL → SORI v0.3 통합 문법 자동 변환.

변환 규칙
- app "이름"                       → sori.toml [app] name
- route M "/p" public|protected:   → route M "/p" (body: PIn) public | guard bearer:
- input f: str(a, b) …             → type PIn: f: Str(a, b) …   (int→Int, float→Float, bool→Bool)
- return {...}                     → return {...}  (input.f → body.f, True/False/None → true/false/none)
- worker "n" "url" timeout t       → sori.toml [workers."n"] url/timeout_ms + use std.worker
- invoke "n"                       → return worker.call("n", body)
- v0.1 의 JSON 전용 본문 / 64KiB 제한은 sori.toml [security] body_types=["json"], max_body_kb=64 로 보존

자동 변환할 수 없는 부분은 report 에 파일 위치·원인·수정 방법을 남긴다.
"""
import ast
import json
import os
import re

from ..compiler import parse as legacy_parse

TYPE_MAP = {"str": "Str", "int": "Int", "float": "Float", "bool": "Bool"}


class MigrationError(Exception):
    pass


def _num(x):
    if isinstance(x, float):
        return repr(x) if not x.is_integer() else f"{x:.1f}"
    return str(x)


def _str_lit(s):
    out = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return '"' + out.replace("{", "{{").replace("}", "}}") + '"'


def expr_to_sori(node, var="body"):
    if isinstance(node, ast.Dict):
        return "{" + ", ".join(f"{expr_to_sori(k, var)}: {expr_to_sori(v, var)}" for k, v in zip(node.keys, node.values)) + "}"
    if isinstance(node, (ast.List, ast.Tuple)):
        return "[" + ", ".join(expr_to_sori(e, var) for e in node.elts) + "]"
    if isinstance(node, ast.Constant):
        v = node.value
        if v is None:
            return "none"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, str):
            return _str_lit(v)
        return _num(v)
    if isinstance(node, ast.Attribute):
        return f"{var}.{node.attr}"
    if isinstance(node, ast.BinOp):
        op = "+" if isinstance(node.op, ast.Add) else "-"
        return f"({expr_to_sori(node.left, var)} {op} {expr_to_sori(node.right, var)})"
    if isinstance(node, ast.UnaryOp):
        return f"(-{expr_to_sori(node.operand, var)})"
    if isinstance(node, ast.Compare):
        sym = {ast.Eq: "==", ast.NotEq: "!=", ast.Gt: ">", ast.GtE: ">=", ast.Lt: "<", ast.LtE: "<="}[type(node.ops[0])]
        return f"({expr_to_sori(node.left, var)} {sym} {expr_to_sori(node.comparators[0], var)})"
    raise MigrationError(f"변환할 수 없는 식: {type(node).__name__}")


def _type_name(path, used):
    parts = [p for p in re.split(r"[/_\-]+", path) if p]
    base = "".join(p[:1].upper() + p[1:] for p in parts) or "Root"
    if base[0].isdigit():
        base = "R" + base
    name, i = base + "In", 2
    while name in used:
        name, i = f"{base}{i}In", i + 1
    used.add(name)
    return name


def _toml_str(s):
    return json.dumps(s, ensure_ascii=False)


def migrate_source(src, source_name="app.sori"):
    """반환: (files: {이름: 내용}, report: [문자열])"""
    program = legacy_parse(src)
    report = []
    used, types_out, routes_out = set(), [], []
    needs_worker = False
    for r in program.routes:
        loc = f"{source_name}: {r.method} {r.path}"
        params = ""
        if r.fields:
            tname = _type_name(r.path, used)
            lines = [f"type {tname}:", f'    """{r.method} {r.path} 입력 (v0.1 input 선언에서 변환)"""']
            for f in r.fields:
                t = TYPE_MAP[f.kind]
                bounds = "" if f.kind == "bool" else f"({_num(f.minimum)}, {_num(f.maximum)})"
                lines.append(f"    {f.name}: {t}{bounds}")
            types_out.append("\n".join(lines))
            params = f" (body: {tname})"
        elif r.method == "POST":
            report.append(f"[동작 차이] {loc}: v0.1 은 입력 없는 POST 의 본문이 정확히 {{}} 인지 검사했지만 v0.3 은 본문을 읽지 않아요. "
                          "본문 검사가 필요하면 필드를 가진 type 을 선언하고 (body: 타입) 을 추가하세요")
        access = "public" if r.access == "public" else "guard bearer"
        head = f'route {r.method} "{r.path}"{params} {access}:'
        if r.worker_name:
            needs_worker = True
            payload = "body" if r.fields else "{}"
            body = f'    return worker.call({_str_lit(r.worker_name)}, {payload})'
        else:
            try:
                body = f"    return {expr_to_sori(r.expression)}"
            except MigrationError as e:
                report.append(f"[수동 수정 필요] {loc}: {e} — 반환식을 v0.3 문법으로 직접 옮기세요")
                body = '    error("migration: manual fix required", 500)'
        routes_out.append(head + "\n" + body)
    header = [f"# '{source_name}' (SORI v0.1 DSL) 에서 sori migrate 로 자동 변환한 파일.",
              "# 접근 정책(public/protected→guard bearer), 입력 범위, 워커 고정 주소는 그대로 보존돼요."]
    if needs_worker:
        header.append("use std.worker")
    app_src = "\n".join(header) + "\n\n" + "\n\n".join(types_out + routes_out) + "\n"
    toml = [
        "[app]", f"name = {_toml_str(program.name)}", 'server = "uvicorn"', "",
        "[security]", "strict_inputs = true", 'body_types = ["json"]   # v0.1 과 같이 JSON 본문만', "max_body_kb = 64        # v0.1 64KiB 제한", "",
    ]
    for w in program.workers:
        toml += [f"[workers.{_toml_str(w.name)}]", f"url = {_toml_str(w.url)}", f"timeout_ms = {w.timeout_ms}", ""]
    toml += ["[permissions]", "# v0.1 프로그램은 외부 효과가 없었어요 (워커 제외)", ""]
    report.insert(0, f"[변환] 라우트 {len(program.routes)}개, 입력 타입 {len(types_out)}개, 워커 {len(program.workers)}개")
    if any(r.access == "protected" for r in program.routes):
        report.append("[유지] protected → guard bearer: SORI_API_TOKEN(32자 이상) 이 없으면 서버가 기동을 거부해요 (v0.1 과 동일)")
    return {"sori.toml": "\n".join(toml), "app.sori": app_src}, report


def migrate_file(path, out_dir, force=False):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    files, report = migrate_source(src, os.path.basename(path))
    if os.path.exists(out_dir) and os.listdir(out_dir) and not force:
        raise MigrationError(f"'{out_dir}' 가 비어 있지 않아요 (덮어쓰려면 --force)")
    os.makedirs(out_dir, exist_ok=True)
    for name, content in files.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write(content)
    return files, report
