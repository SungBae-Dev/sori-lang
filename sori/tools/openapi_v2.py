"""Typed IR v2 → OpenAPI 3.1.

원칙: 보수적으로, 사실만 기술한다.
- `guard bearer` 만 bearerAuth 로 표기한다. 사용자 정의 guard 는 OpenAPI 보안 스키마로 정확히 표현할 수
  없으므로 `x-sori-access` 확장 + 403 응답 + 설명으로만 기록하고, bearer 로 잘못 표기하지 않는다.
- 응답 스키마는 정적 타입/반환식 모양에서 확실한 만큼만 쓰고 나머지는 빈 스키마({})로 둔다.
"""
import re

from .. import __version__

_SCALAR = {"Int": {"type": "integer"}, "Float": {"type": "number"}, "Str": {"type": "string"},
           "Bool": {"type": "boolean"}, "None": {"type": "null"}, "Html": {"type": "string"},
           "Secret": {"type": "string", "format": "password"}}


def schema_of_tyir(t, inline=None):
    """타입 IR → JSON Schema. inline: 레코드 정의 dict 를 주면 $ref 대신 펼친다(AI 툴 스키마용)."""
    if t is None:
        return {}
    k = t["k"]
    if k == "Opt":
        inner = schema_of_tyir(t["of"], inline)
        if "type" in inner and isinstance(inner["type"], str):
            return dict(inner, type=[inner["type"], "null"])
        return {"anyOf": [inner, {"type": "null"}]}
    if k in ("Any", "Json"):
        s = {}
    elif k == "List":
        s = {"type": "array", "items": schema_of_tyir(t["of"], inline)}
    elif k == "Map":
        s = {"type": "object", "additionalProperties": schema_of_tyir(t["of"], inline)}
    elif k == "Ref":
        if inline is not None and t["name"] in inline:
            return record_schema(inline[t["name"]], inline)
        return {"$ref": f"#/components/schemas/{t['name']}"}
    else:
        s = dict(_SCALAR.get(k, {}))
    if "lo" in t:
        key = {"Str": ("minLength", "maxLength"), "Secret": ("minLength", "maxLength"),
               "List": ("minItems", "maxItems")}.get(k, ("minimum", "maximum"))
        s[key[0]], s[key[1]] = t["lo"], t["hi"]
    return s


def record_schema(rec, inline=None, depth=0):
    props, req = {}, []
    for f in rec["fields"]:
        props[f["name"]] = schema_of_tyir(f["type"], inline if depth < 6 else None)
        if f["default"] is None and f["type"]["k"] != "Opt":
            req.append(f["name"])
    s = {"type": "object", "properties": props, "required": req, "additionalProperties": False}
    if rec.get("doc"):
        s["description"] = rec["doc"]
    return s


def schema_of_static(t, records):
    """정적 타입 문자열 → JSON Schema (모르면 {})."""
    if not t:
        return {}
    opt = t.endswith("?")
    base = t[:-1] if opt else t
    if base in _SCALAR:
        s = dict(_SCALAR[base])
    elif base.startswith("List[") and base.endswith("]"):
        s = {"type": "array", "items": schema_of_static(base[5:-1], records)}
    elif base.startswith("Map[") and base.endswith("]"):
        s = {"type": "object", "additionalProperties": schema_of_static(base[4:-1], records)}
    elif base in records:
        s = {"$ref": f"#/components/schemas/{base}"}
    else:
        s = {}
    if opt and s:
        if isinstance(s.get("type"), str):
            s = dict(s, type=[s["type"], "null"])
        else:
            s = {"anyOf": [s, {"type": "null"}]}
    return s


def schema_of_expr(node, records):
    """반환식 모양에서 스키마를 만든다 (맵/목록 리터럴은 구조까지)."""
    op = node.get("op")
    if op == "map" and all(k.get("op") == "lit" for k, _ in node["pairs"]):
        props = {k["v"]: schema_of_expr(v, records) for k, v in node["pairs"]}
        return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}
    if op == "list":
        items = [schema_of_expr(x, records) for x in node["items"]]
        return {"type": "array", "items": items[0] if items and all(i == items[0] for i in items) else {}}
    return schema_of_static(node.get("t"), records)


def _walk(stmts):
    for st in stmts or []:
        yield st
        op = st["op"]
        if op == "if":
            for _, body in st["branches"]:
                yield from _walk(body)
            yield from _walk(st.get("else"))
        elif op in ("while", "for"):
            yield from _walk(st["body"])
        elif op == "try":
            yield from _walk(st["body"])
            yield from _walk(st["handler"])


def _walk_expr(n):
    if isinstance(n, dict):
        yield n
        for v in n.values():
            if isinstance(v, (dict, list)):
                yield from _walk_expr(v)
    elif isinstance(n, list):
        for v in n:
            yield from _walk_expr(v)


def _builtin_call(n, name):
    return n.get("op") == "call" and n["fn"].get("op") == "var" and n["fn"].get("scope") == "builtin" \
        and n["fn"].get("name") == name


def responses_for(route, records):
    out = {}
    for st in _walk(route["body"]):
        if st["op"] != "return":
            continue
        x = st.get("x")
        if x is None:
            out.setdefault("204", {"description": "No content"})
            continue
        if _builtin_call(x, "redirect"):
            out["303"] = {"description": "Redirect (same-origin only)"}
            continue
        if _builtin_call(x, "respond") and x["args"] and x["args"][0].get("op") == "lit":
            code = str(x["args"][0]["v"])
            body = x["args"][1] if len(x["args"]) > 1 else None
            entry = {"description": "Response"}
            if body is not None:
                entry["content"] = _content(body, records)
            out[code] = entry
            continue
        out.setdefault("200", {"description": "Successful response", "content": _content(x, records)})
    for n in _walk_expr(route["body"]):
        if _builtin_call(n, "error"):
            code = "400"
            if len(n["args"]) > 1 and n["args"][1].get("op") == "lit":
                code = str(n["args"][1]["v"])
            out.setdefault(code, {"description": "Application error"})
    if not out:
        out["204"] = {"description": "No content"}
    return out


def _content(expr, records):
    t = (expr.get("t") or "").rstrip("?")
    if t == "Html":
        return {"text/html": {"schema": {"type": "string"}}}
    if t == "Str":
        return {"text/plain": {"schema": {"type": "string"}}}
    return {"application/json": {"schema": schema_of_expr(expr, records)}}


def operation_id(method, path):
    slug = re.sub(r"[{}]", "", path).strip("/").replace("/", "_") or "root"
    return re.sub(r"[^A-Za-z0-9_]", "_", f"{method.lower()}_{slug}")


def openapi(ir, config=None):
    config = config or {}
    records = {t["name"]: t for t in ir["types"]}
    body_types = tuple(config.get("security", {}).get("body_types", ("json", "form")))
    max_kb = int(config.get("security", {}).get("max_body_kb", 1024))
    paths = {}
    used_bearer = False
    for r in ir["routes"]:
        op = {"operationId": operation_id(r["method"], r["path"]), "responses": responses_for(r, records),
              "x-sori-effects": r.get("effects", [])}
        if r.get("doc"):
            op["summary"] = r["doc"].splitlines()[0][:120]
            op["description"] = r["doc"]
        params, body = [], None
        for p in r["params"]:
            if p["source"] in ("path", "query"):
                params.append({"name": p["name"], "in": p["source"],
                               "required": p["source"] == "path" or (p.get("default") is None and p["type"]["k"] != "Opt"),
                               "schema": schema_of_tyir(p["type"])})
            elif p["source"] == "body":
                body = p
        if params:
            op["parameters"] = params
        if body is not None:
            schema = schema_of_tyir(body["type"])
            content = {}
            if "json" in body_types:
                content["application/json"] = {"schema": schema}
            if "form" in body_types:
                content["application/x-www-form-urlencoded"] = {"schema": schema}
            op["requestBody"] = {"required": body.get("default") is None, "content": content}
            op["responses"].setdefault("413", {"description": f"Request too large (> {max_kb} KiB)"})
            op["responses"].setdefault("415", {"description": "Unsupported media type"})
        if params or body is not None:
            op["responses"].setdefault("400", {"description": "Input does not match declared type/bounds"})
        acc = r["access"]
        op["x-sori-access"] = acc["kind"] if acc["kind"] != "guard" else f"guard:{acc['guard']}"
        if acc["kind"] == "public":
            op["security"] = []
        elif acc["kind"] == "bearer":
            used_bearer = True
            op["security"] = [{"bearerAuth": []}]
            op["responses"].setdefault("401", {"description": "Missing or invalid bearer token"})
        elif acc["kind"] == "guard":
            # 사용자 정의 guard: 실제 인증 방식은 guard 코드가 결정한다 — bearer 로 표기하지 않는다.
            g = next((x for x in ir["guards"] if x["name"] == acc["guard"]), None)
            note = f"사용자 정의 guard `{acc['guard']}` 가 요청을 검사한다."
            if g and g.get("doc"):
                note += " " + g["doc"]
            op["description"] = (op.get("description", "") + "\n\n" + note).strip()
            op["responses"].setdefault("403", {"description": f"Rejected by guard {acc['guard']}"})
        else:
            op["responses"].setdefault("403", {"description": "Denied by default (no access policy)"})
        if set(r.get("effects", [])) & {"worker", "ai"}:
            op["responses"].setdefault("502", {"description": "Upstream (worker/AI) unavailable or invalid output"})
        op["responses"].setdefault("429", {"description": "Rate limited"})
        op["responses"].setdefault("500", {"description": "Internal error (request_id only)"})
        oas_path = r["path"]
        paths.setdefault(oas_path, {})[r["method"].lower()] = op
    spec = {
        "openapi": "3.1.0",
        "info": {"title": ir["app"], "version": __version__,
                 "description": f"Generated from SORI Typed IR {ir['ir_version']}. Not a security audit."},
        "paths": paths,
        "components": {"schemas": {name: record_schema(rec) for name, rec in sorted(records.items())}},
    }
    if used_bearer:
        spec["components"]["securitySchemes"] = {"bearerAuth": {"type": "http", "scheme": "bearer"}}
    return spec


def tool_schemas(ir):
    """라우트 → AI 에이전트 툴 정의 (레코드 스키마는 펼쳐서 자기완결적으로)."""
    records = {t["name"]: t for t in ir["types"]}
    out = []
    for r in ir["routes"]:
        if r["access"]["kind"] == "deny":
            continue
        props, req = {}, []
        for p in r["params"]:
            if p["source"] == "req":
                continue
            props[p["name"]] = schema_of_tyir(p["type"], inline=records)
            if p.get("default") is None and p["type"]["k"] != "Opt":
                req.append(p["name"])
        desc = (r.get("doc") or f"{r['method']} {r['path']}") + f"  [HTTP {r['method']} {r['path']}]"
        acc = r["access"]
        if acc["kind"] == "bearer":
            desc += " (인증 필요: Authorization: Bearer 토큰)"
        elif acc["kind"] == "guard":
            desc += f" (인증 필요: 사용자 정의 guard {acc['guard']})"
        if r.get("effects"):
            desc += f" (effects: {', '.join(r['effects'])})"
        out.append({"name": operation_id(r["method"], r["path"])[:64], "description": desc,
                    "input_schema": {"type": "object", "properties": props, "required": req,
                                     "additionalProperties": False}})
    return out
