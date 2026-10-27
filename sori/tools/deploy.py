"""배포·AI 연동 도구: Dockerfile, Kubernetes 매니페스트(권한 → NetworkPolicy), AI 컨텍스트, 툴 스키마, 감사."""
import importlib.metadata
import json
import os
import re
import shutil

from ..framework.app import VERSION
from ..lang.compiler import IR_VERSION
from .openapi_v2 import openapi as openapi_v2, tool_schemas

TYPE_SCHEMA = {"Int": {"type": "integer"}, "Float": {"type": "number"}, "Str": {"type": "string"},
               "Bool": {"type": "boolean"}, "Json": {}, "Secret": {"type": "string", "format": "password"}}


def type_str(t):
    if t is None:
        return "Request"
    s = t.name + ("[" + ", ".join(type_str(a) for a in t.args) + "]" if t.args else "")
    if getattr(t, "bounds", None):
        s += f"({t.bounds[0]}, {t.bounds[1]})"
    return s + ("?" if t.optional else "")


def schema_of(t, project, depth=0):
    if t is None or depth > 8:
        return {}
    if t.name in TYPE_SCHEMA:
        s = dict(TYPE_SCHEMA[t.name])
    elif t.name == "List":
        s = {"type": "array", "items": schema_of(t.args[0], project, depth + 1) if t.args else {}}
    elif t.name == "Map":
        s = {"type": "object", "additionalProperties": schema_of(t.args[-1], project, depth + 1) if t.args else {}}
    elif t.name in project.types:
        decl = project.types[t.name]
        props, req = {}, []
        for f in decl.fields:
            props[f.name] = schema_of(f.typ, project, depth + 1)
            if f.default is None and not f.typ.optional:
                req.append(f.name)
        s = {"type": "object", "properties": props, "required": req, "additionalProperties": False}
        if decl.doc:
            s["description"] = decl.doc
    else:
        s = {}
    if getattr(t, "bounds", None):
        lo, hi = t.bounds
        keys = {"Str": ("minLength", "maxLength"), "Secret": ("minLength", "maxLength"), "List": ("minItems", "maxItems")}.get(t.name, ("minimum", "maximum"))
        s[keys[0]], s[keys[1]] = lo, hi
    if t.optional:
        s["nullable"] = True
    return s


def tools(app):
    """라우트 → AI 에이전트 툴 스키마 (Typed IR v2 기반)."""
    return tool_schemas(app.ir)


def canonical_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def manifest(app):
    """AI·도구용 요약 매니페스트 (비밀값·워커 URL 제외)."""
    ir = app.ir
    return {
        "schema_version": "sori/manifest/v2",
        "ir_version": ir["ir_version"],
        "app": ir["app"],
        "permissions": ir["permissions"],
        "workers": [w["name"] for w in ir["workers"]],
        "routes": [{"method": r["method"], "path": r["path"], "access": r["access"]["kind"],
                    "guard": r["access"].get("guard"), "effects": r["effects"], "returns": r["returns"],
                    "params": [{"name": p["name"], "source": p["source"], "type": p["type"]} for p in r["params"]]}
                   for r in ir["routes"]],
        "tasks": [{"name": t["name"], "period_ms": t["period_ms"], "effects": t["effects"]} for t in ir["tasks"]],
    }


def build_spec(app, out):
    """명세 산출물: manifest / typed-ir(v2) / openapi / tools. 네이티브 바이너리는 만들지 않는다."""
    os.makedirs(out, exist_ok=True)
    artifacts = {"manifest.json": manifest(app), "typed-ir.json": app.ir,
                 "openapi.json": openapi_v2(app.ir, app.config), "tools.json": tool_schemas(app.ir)}
    for name, value in artifacts.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(canonical_json(value))
    return sorted(artifacts)


# ---------------------------------------------------------------- AI 컨텍스트
CHEATSHEET = """## SORI v0.3 문법 요약 (LLM 이 정확한 코드를 쓰기 위한 규칙)
- 정적 타입 검사: 타입이 확실히 틀린 연산/대입/호출은 컴파일 오류 (SORI-E107/E108)
- 외부 입력은 범위 필수 (strict_inputs 기본 켜짐): Str(1, 80), Int(0, 100), List[T](0, 20)
- 파이썬식 들여쓰기(스페이스 4칸), 큰따옴표 문자열만, 주석은 `#`
- `let x = 1` 불변, `var y = 2` 가변. 재할당은 var 만 가능 (SORI-E102)
- 문자열 보간: `"안녕 {name}"` — 보간 안에는 문자열 리터럴 금지
- `sql"... {값} ..."` → 자동 파라미터 바인딩. db 는 sql 리터럴만 받음 (문자열 SQL = 런타임 거부)
- `html"<p>{값}</p>"` → 문맥별 자동 이스케이프. `<script>`/on* 속성/style 안 보간은 컴파일 오류 (SORI-E401)
- 레코드: `type Todo:` 아래 `필드: 타입 [= 기본값]`. 불변. 변경은 `t.copy(done=true)`
- 타입: Int Float Str Bool Json Html Secret List[T] Map[V] 레코드이름, `T?` = none 허용
- 입력 범위: `Str(1, 80)` 길이, `Int(0, 100)` 값, `List[Str](0, 20)` 개수 — 외부 입력에는 범위를 꼭 적기 (W304/E305)
- 함수: `fn 이름(a: Int, b: Str = "x") -> Str:` / 람다: `fn(x) => x * 2`
- 라우트: `route GET "/todos/{id}" (id: Int(1, 1000000)) public:` 또는 `... guard 이름:` — 접근 정책 없으면 컴파일 오류 (SORI-E301)
  - 파라미터 출처: 경로 {이름} → 경로, `body: 레코드` → JSON/폼 본문(선언 외 필드 거부), `req` → 요청 객체, 나머지 → 쿼리
  - 반환: Html → text/html, Str → text/plain, 레코드/맵/리스트 → JSON, `respond(상태, 본문)`, `redirect("/경로")`
- guard: `guard admin(req):` 가 true 를 돌려줘야 통과. 내장 `guard bearer` = Authorization: Bearer $SORI_API_TOKEN (32자 이상, 없으면 기동 거부)
- 격리 워커: `use std.worker` → `worker.call("이름", 값, 결과타입)` (sori.toml [workers.이름] 루프백 주소, 별도 프로세스의 파이썬/ML/ROS)
- 주기 작업: `task 이름 every 50 ms:` (피지컬 AI 제어 루프/센서 폴링)
- 테스트: `test "이름":` 블록 + `expect(조건)` + `client.get/post(...)`
- 모듈: `use std.db|http|fs|env|ai|json|time|log|crypto|worker`. 파이썬/ML/ROS 는 `std.worker` 로 별도 프로세스 호출 (`use py` 는 개발 전용, 운영 기동 거부)
- 금지: `_` 로 시작하는 이름/속성, `.format`, eval/import, 동적 속성 접근 (실행은 IR 해석기 — 코드 생성 없음)
- 오류 처리: `try:` ... `catch e:` (e.message). 보안 위반(SecurityError)은 catch 로 못 잡음
- 비밀값: `env.secret("KEY")` → Secret (출력/로그/JSON 에서 ***), 실제 값은 `.reveal()`
- AI: `ai.ask(프롬프트)`, `ai.extract(레코드타입, 텍스트)` (결과는 타입 검증됨), `ai.classify(텍스트, [라벨들])`
"""


def context(app):
    p = app.project
    L = [f"# SORI_CONTEXT — {app.config.get('app', {}).get('name', os.path.basename(app.root))}",
         "", "이 파일은 AI 코딩 도우미가 이 프로젝트를 정확히 이해하도록 `sori context` 가 생성했어요.", "", CHEATSHEET,
         "## 이 프로젝트의 권한 (sori.toml [permissions])", "```json", json.dumps(app.perms, ensure_ascii=False, indent=2), "```", "",
         "## 타입"]
    for name, d in p.types.items():
        L.append(f"- `{name}`: " + ", ".join(f"{f.name}: {type_str(f.typ)}" + (" = …" if f.default is not None else "") for f in d.fields)
                 + (f" — {d.doc}" if d.doc else ""))
    L += ["", "## 라우트"]
    for r in p.routes:
        params = ", ".join(f"{n}: {type_str(t)}" for n, t, _ in r["params"])
        acc = "public" if r["access"] == "public" else f"guard {r['guard']}"
        L.append(f"- `{r['method']} {r['path']}` ({params}) {acc} — {r['doc'] or ''} [{r['file']}:{r['line']}]")
    L += ["", "## guard"] + [f"- `{g}`" for g in p.guards]
    L += ["", "## 주기 작업"] + [f"- `{t['name']}` 매 {t['period'] * 1000:g} ms — {t['doc'] or ''}" for t in p.tasks]
    L += ["", "## 함수"] + [f"- `{n}({', '.join(pp.name + ': ' + type_str(pp.typ) for pp in f.params)})`"
                            + (f" -> {type_str(f.ret)}" if f.ret else "") + (f" — {f.doc}" if f.doc else "") for n, f in p.fns.items()]
    L += ["", f"## 테스트: {len(p.tests)}개 (`sori test` 로 실행)", "",
          "## 검증 루프", "코드를 고친 뒤 `sori check --json` 으로 진단(JSON)을 받고, 각 항목의 code/hint 를 따라 수정하세요."]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- 보안 감사
def audit(app):
    p = app.project
    L = ["== SORI 보안 감사 ==", "", "[권한 표면]"]
    perms = app.perms
    for k in ("net", "net_private", "fs_read", "fs_write", "env", "db", "python"):
        if perms.get(k):
            L.append(f"  {k:12s} {', '.join(map(str, perms[k]))}")
    if not any(perms.get(k) for k in perms):
        L.append("  (외부 효과 없음 — 최소 권한)")
    for name, cfg in app.config.get("workers", {}).items():
        L.append(f"  worker       {name} → {cfg.get('url')} (timeout {cfg.get('timeout_ms', 1000)}ms, 별도 프로세스)")
    if app.config.get("security", {}).get("strict_inputs"):
        L.append("  strict_inputs 켜짐 — 범위 없는 입력은 컴파일 오류")
    L += ["", "[라우트 접근 정책]"]
    for r in p.routes:
        flag = "  ⚠ 공개 쓰기" if r["access"] == "public" and r["method"] != "GET" else ""
        acc = {"public": "public", "bearer": "guard bearer"}.get(r["access"], f"guard {r['guard']}")
        eff = ",".join(r.get("effects", [])) or "-"
        L.append(f"  {r['method']:6s} {r['path']:28s} {acc:16s} effects={eff}{flag}")
    if p.uses_bearer:
        L.append("  (guard bearer: SORI_API_TOKEN 32자 미만/누락 시 기동 거부)")
    warns = [d for d in p.diags if d.severity == "warning"]
    L += ["", "[경고]"] + ([f"  SORI-{d.code} {d.file}:{d.line} {d.message}" for d in warns] or ["  없음"])
    py = [u for u in p.uses if u[0] == "py"]
    L += ["", "[신뢰 경계: 파이썬 패키지]"]
    if py:
        for _, name, f, line in py:
            L.append(f"  {name} ({f}:{line}) — 개발 전용. 패키지 내부 코드는 SORI 정책 밖에서 실행되며 운영에서는 기동 거부돼요")
    else:
        L.append("  없음")
    L += ["", "[기본 적용 방어]",
          "  SQLi(파라미터 바인딩 강제) · XSS(문맥별 이스케이프+CSP) · CSRF(Origin 검사) · SSRF(내부망 차단+IP 고정)",
          "  경로 탈출 · 요청 스머글링(TE 거부, 중복 헤더 거부) · 압축 본문 거부 · Mass assignment · 중복 JSON 키",
          "  파라미터 오염 · 오픈 리다이렉트 · CRLF 인젝션 · 비밀값 마스킹 · 동적 실행 없음(IR 해석) · 실행 상한 · 레이트 리밋",
          "", "[검증되지 않은 영역]",
          "  외부 침투 테스트·퍼징·형식 검증 미실시. IR 해석기는 언어 의미론 실행기이며 OS 수준 격리가 아니에요.",
          "  CPython·uvicorn·OS 자체 취약점의 영향은 받아요 (docs/SECURITY.ko.md)."]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- 빌드 (Docker)
DOCKERFILE = """# SORI 가 생성한 Dockerfile — 비루트, 최소 이미지, 소스 무결성 검증
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SORI_ENV=production PORT={port}
RUN groupadd -g 10001 sori && useradd -r -u 10001 -g sori -d /app -s /usr/sbin/nologin sori
WORKDIR /app
{pip}COPY runtime/ /opt/sori/
COPY app/ /app/
ENV PYTHONPATH=/opt/sori
{writable}USER 10001:10001
EXPOSE {port}
HEALTHCHECK --interval=10s --timeout=2s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:{port}/healthz', timeout=2)"]
ENTRYPOINT ["python", "-m", "sori", "run", "/app", "--host", "0.0.0.0", "--server", "uvicorn"]
"""


def write_lock(app):
    lock = {"sori_version": VERSION, "files": app.lock_digest(), "python": {}}
    for pkg in sorted(app.caps.python):
        try:
            lock["python"][pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            lock["python"][pkg] = None
    with open(os.path.join(app.root, "sori.lock"), "w", encoding="utf-8") as f:
        json.dump(lock, f, ensure_ascii=False, indent=2)
    return lock


def build_oci(app, out=None):
    """OCI(Docker) 빌드 컨텍스트 + sori.lock. 이미지 자체를 빌드하지는 않는다."""
    lock = write_lock(app)
    out = out or os.path.join(app.root, ".sori", "build")
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(os.path.join(out, "app"))
    # sori 패키지 전체 (CLI·컴파일러·런타임·도구). 이 파일은 sori/tools/ 에 있으므로 한 단계 위가 패키지 루트.
    pkg_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shutil.copytree(pkg_src, os.path.join(out, "runtime", "sori"), ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # 프로젝트 파일: sori.lock 이 해시한 범위와 정확히 같은 목록만 복사 (해시되지 않은 파일은 이미지에 없음)
    for rel in app.deploy_files() + ["sori.lock"]:
        src = os.path.join(app.root, rel)
        dst = os.path.join(out, "app", rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
    pip = ""
    pins = [f"{k}=={v}" for k, v in lock["python"].items() if v]
    # 운영 이미지는 항상 uvicorn (내장 서버는 개발 전용 — 운영 기동 시 거부됨)
    try:
        pins.append(f"uvicorn=={importlib.metadata.version('uvicorn')}")
    except importlib.metadata.PackageNotFoundError:
        pins.append("uvicorn>=0.34,<1")
    if pins:
        with open(os.path.join(out, "requirements.txt"), "w") as f:
            f.write("\n".join(pins) + "\n")
        pip = ("COPY requirements.txt /tmp/requirements.txt\n"
               "RUN pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt\n")
    port = int(app.config.get("app", {}).get("port", 8080))
    writable = writable_dirs(app)
    wr = ""
    if writable:
        paths = " ".join("/app/" + w for w in writable)
        wr = f"RUN mkdir -p {paths} && chown 10001:10001 {paths}\n"
    with open(os.path.join(out, "Dockerfile"), "w") as f:
        f.write(DOCKERFILE.format(port=port, pip=pip, writable=wr))
    with open(os.path.join(out, ".dockerignore"), "w") as f:
        f.write("**/__pycache__\n**/*.pyc\n.git\n")
    return out


# ---------------------------------------------------------------- Kubernetes
def writable_dirs(app):
    """쓰기 권한이 필요한 경로 (fs_write + sqlite 파일의 디렉터리). 이미지에서는 10001 소유, k8s 에서는 emptyDir."""
    perms = app.perms
    out = set(perms.get("fs_write", [])) | {os.path.dirname(d[len("sqlite:"):]) for d in perms.get("db", [])
                                             if d.startswith("sqlite:") and d != "sqlite::memory:"}
    clean = []
    for w in sorted(out):
        w = os.path.normpath(w) if w else ""
        if w and w != "." and not w.startswith("..") and not os.path.isabs(w):
            clean.append(w)
    return clean


def k8s(app, image=None, replicas=2):
    name = re.sub(r"[^a-z0-9-]", "-", app.config.get("app", {}).get("name", os.path.basename(app.root)).lower()).strip("-") or "sori-app"
    port = int(app.config.get("app", {}).get("port", 8080))
    image = image or f"{name}:latest"
    perms = app.perms
    writable = writable_dirs(app)
    mounts, vols = [], []
    for i, w in enumerate(writable):
        mounts.append(f"            - name: data{i}\n              mountPath: /app/{w}")
        vols.append(f"        - name: data{i}\n          emptyDir: {{}}")
    mounts.append("            - name: tmp\n              mountPath: /tmp")
    vols.append("        - name: tmp\n          emptyDir: {}")
    env_lines = []
    for e in perms.get("env", []):
        env_lines.append(f"            - name: {e}\n              valueFrom:\n                secretKeyRef:\n"
                         f"                  name: {name}-secrets\n                  key: {e}\n                  optional: true")
    required = list(app.config.get("secrets", {}))
    if app.project.uses_bearer:
        required.append("SORI_API_TOKEN")
    for e in required:
        if e in perms.get("env", []):
            continue
        env_lines.append(f"            - name: {e}\n              valueFrom:\n                secretKeyRef:\n"
                         f"                  name: {name}-secrets\n                  key: {e}")
    env_block = ("          env:\n" + "\n".join(env_lines) + "\n") if env_lines else ""
    sidecars = ""
    for wname, wcfg in app.config.get("workers", {}).items():
        if not wcfg.get("command"):
            continue
        cmd = ", ".join(json.dumps(c) for c in wcfg["command"])
        sidecars += f"""        - name: worker-{re.sub(r'[^a-z0-9-]', '-', wname.lower())}
          image: {image}
          imagePullPolicy: IfNotPresent
          workingDir: /app
          command: [{cmd}]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {{drop: ["ALL"]}}
          resources:
            requests: {{cpu: 50m, memory: 64Mi}}
            limits: {{cpu: 500m, memory: 512Mi}}
"""
    hosts = []
    for entry in perms.get("net", []):
        e = entry.lower()
        h = re.sub(r"^\w+://", "", e).split(":")[0].split("/")[0]
        hosts.append(h)
    egress = "    - to:\n        - namespaceSelector: {}\n      ports:\n        - protocol: UDP\n          port: 53\n        - protocol: TCP\n          port: 53\n"
    if hosts:
        egress += "    - ports:\n        - protocol: TCP\n          port: 443\n"
    from ..framework.app import metrics_mode
    if metrics_mode(app.config) == "public":
        annotations = f'      annotations:\n        prometheus.io/scrape: "true"\n        prometheus.io/port: "{port}"\n'
    else:
        # 기본(token): /metrics 는 SORI_METRICS_TOKEN Bearer 가 있어야 응답 — 어노테이션 기반 무인증 스크랩은 쓰지 않음.
        # Prometheus Operator 를 쓴다면 ServiceMonitor 의 bearerTokenSecret 으로 같은 토큰을 지정하세요.
        annotations = '      annotations:\n        sori.dev/metrics: "token (SORI_METRICS_TOKEN, ServiceMonitor bearerTokenSecret)"\n'
    deploy = f"""# SORI 가 sori.toml 권한에서 생성한 매니페스트 (최소 권한)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  labels: {{app: {name}, managed-by: sori}}
spec:
  replicas: {replicas}
  selector:
    matchLabels: {{app: {name}}}
  template:
    metadata:
      labels: {{app: {name}}}
{annotations}    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile: {{type: RuntimeDefault}}
      containers:
        - name: app
          image: {image}
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: {port}
{env_block}          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {{drop: ["ALL"]}}
          resources:
            requests: {{cpu: 100m, memory: 128Mi}}
            limits: {{cpu: "1", memory: 512Mi}}
          readinessProbe:
            httpGet: {{path: /readyz, port: {port}}}
            periodSeconds: 5
          livenessProbe:
            httpGet: {{path: /healthz, port: {port}}}
            periodSeconds: 10
          volumeMounts:
{chr(10).join(mounts)}
{sidecars}      volumes:
{chr(10).join(vols)}
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
spec:
  selector: {{app: {name}}}
  ports:
    - port: 80
      targetPort: {port}
---
# 기본 거부 + sori.toml 의 net 권한만큼만 이그레스 허용
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}-least-privilege
spec:
  podSelector:
    matchLabels: {{app: {name}}}
  policyTypes: [Ingress, Egress]
  ingress:
    - ports:
        - protocol: TCP
          port: {port}
  egress:
{egress}"""
    if hosts:
        fqdn = "\n".join(f"            - matchName: \"{h}\"" if not h.startswith("*.") else f"            - matchPattern: \"{h}\"" for h in hosts)
        deploy += f"""---
# (Cilium 사용 시) 도메인 단위 이그레스 제한: net 권한 = {', '.join(hosts)}
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: {name}-fqdn
spec:
  endpointSelector:
    matchLabels: {{app: {name}}}
  egress:
    - toEndpoints:
        - matchLabels: {{k8s:io.kubernetes.pod.namespace: kube-system, k8s-app: kube-dns}}
      toPorts:
        - ports: [{{port: "53", protocol: ANY}}]
          rules:
            dns: [{{matchPattern: "*"}}]
    - toFQDNs:
{fqdn}
      toPorts:
        - ports: [{{port: "443", protocol: TCP}}]
"""
    return deploy


# ---------------------------------------------------------------- Docker Compose
def compose(app, image=None):
    name = re.sub(r"[^a-z0-9-]", "-", app.config.get("app", {}).get("name", os.path.basename(app.root)).lower()).strip("-") or "sori-app"
    port = int(app.config.get("app", {}).get("port", 8080))
    image = image or f"{name}:latest"
    env = list(app.perms.get("env", [])) + list(app.config.get("secrets", {}))
    if app.project.uses_bearer:
        env.append("SORI_API_TOKEN")
    env_lines = "".join(f"      {e}: ${{{e}:?{e} 를 .env 에 설정하세요}}\n" for e in dict.fromkeys(env))
    hardening = ("    read_only: true\n    tmpfs:\n      - /tmp\n    security_opt:\n      - no-new-privileges:true\n"
                 "    cap_drop:\n      - ALL\n    restart: unless-stopped\n")
    out = f"""# SORI 가 sori.toml 에서 생성한 Compose (로컬 검증용). 워커는 앱의 네트워크 네임스페이스를 공유해 루프백으로만 통신
services:
  app:
    build: .sori/build
    image: {image}
    ports:
      - "127.0.0.1:{port}:{port}"
""" + (f"    environment:\n{env_lines}" if env_lines else "") + hardening
    for wname, wcfg in app.config.get("workers", {}).items():
        if not wcfg.get("command"):
            continue
        cmd = ", ".join(json.dumps(c) for c in wcfg["command"])
        out += f"""  worker-{re.sub(r'[^a-z0-9-]', '-', wname.lower())}:
    image: {image}
    depends_on:
      - app
    network_mode: "service:app"
    working_dir: /app
    entrypoint: [{cmd}]
""" + hardening
    return out


# ---------------------------------------------------------------- 새 프로젝트
NEW_TOML = """[app]
name = "{name}"
port = 8080
server = "uvicorn"     # 운영 기본: ASGI(uvicorn). 의존성 없는 내장 서버는 'sori dev' 전용

[security]
strict_inputs = true   # 범위 없는 외부 입력은 컴파일 오류 (기본값, 운영에서 끌 수 없음)
metrics = "token"      # /metrics 는 SORI_METRICS_TOKEN Bearer 가 있어야 응답 (기본). "public" | "off"

[permissions]
# 이 앱이 할 수 있는 일만 적어요. 적지 않은 건 전부 거부돼요.
db = ["sqlite:./data/app.db"]
# net = ["api.anthropic.com"]
# env = ["ANTHROPIC_API_KEY"]
# 파이썬/ML 은 별도 프로세스 워커로:  [workers.model] url = "http://127.0.0.1:9010/invoke"
"""

NEW_APP = '''use std.db

type Note:
    id: Int
    text: Str

type NewNote:
    text: Str(1, 500)

db.exec(sql"CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, text TEXT NOT NULL)")

route GET "/" public:
    """메모 목록 페이지"""
    let notes = db.all(sql"SELECT id, text FROM notes ORDER BY id DESC", Note)
    let items = map(notes, fn(n) => html"<li>{n.text}</li>")
    return html"<h1>메모</h1><ul>{items}</ul>"

route GET "/api/notes" public:
    """메모 목록 JSON"""
    return db.all(sql"SELECT id, text FROM notes ORDER BY id DESC", Note)

route POST "/api/notes" (body: NewNote) public:
    """메모 추가"""
    let r = db.exec(sql"INSERT INTO notes (text) VALUES ({body.text})")
    return respond(201, Note(id=r.last_id, text=body.text))

test "메모를 추가하고 조회할 수 있다":
    let r = client.post("/api/notes", json={text: "첫 메모"})
    expect(r.status == 201)
    expect(len(client.get("/api/notes").json()) >= 1)
'''


def new_project(name):
    if os.path.exists(name):
        raise FileExistsError(f"'{name}' 이(가) 이미 있어요 (덮어쓰지 않아요)")
    os.makedirs(name)
    with open(os.path.join(name, "sori.toml"), "w", encoding="utf-8") as f:
        f.write(NEW_TOML.format(name=os.path.basename(name)))
    with open(os.path.join(name, "app.sori"), "w", encoding="utf-8") as f:
        f.write(NEW_APP)
    with open(os.path.join(name, ".gitignore"), "w", encoding="utf-8") as f:
        f.write(".sori/\n.sori-build/\ndata/\n.env\n__pycache__/\n")
    return name
