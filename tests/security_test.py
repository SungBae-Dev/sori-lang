"""SORI 보안 회귀 테스트 — 컴파일 타임 차단 / 런타임 차단 / 실제 HTTP 서버 공격 시나리오.

실행: python3 tests/security_test.py
"""
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sori.runtime.app import build_app  # noqa: E402
from sori.runtime.core import SecurityError, SoriTypeError, Secret, html, json_dumps  # noqa: E402
from sori.runtime.web import TestClient, dispatch  # noqa: E402

results = []


def case(name, ok, detail=""):
    results.append((name, ok, detail))


def project(src, toml="[permissions]\n"):
    d = tempfile.mkdtemp(prefix="sori_sec_")
    with open(os.path.join(d, "sori.toml"), "w") as f:
        f.write(toml)
    with open(os.path.join(d, "main.sori"), "w") as f:
        f.write(src)
    return d


def expect_code(name, src, code, toml="[permissions]\n"):
    d = project(src, toml)
    try:
        app, diags = build_app(d)
        codes = [x.code for x in diags]
        case(f"[컴파일] {name}", code in codes, f"기대 {code}, 실제 {codes or '없음'}")
    finally:
        shutil.rmtree(d)


# ================================================================ 1) 컴파일 타임 차단
expect_code("샌드박스 탈출: __class__ 접근", 'let x = (1).__class__\n', "E105")
expect_code("샌드박스 탈출: format 문자열 공격", 'let s = "{{0}}".format(1)\n', "E106")
expect_code("런타임 핸들 _R 직접 접근", 'let x = _R\n', "E105")
expect_code("미선언 파이썬 패키지 (os)", 'use py os\n', "E201")
expect_code("net 권한 없이 std.http", 'use std.http\n', "E201")
expect_code("접근 정책 없는 라우트 (기본 거부)", 'route GET "/admin":\n    return "x"\n', "E301")
expect_code("guard 자리에 일반 함수", 'fn f(req):\n    return true\nroute GET "/a" guard f:\n    return "x"\n', "E302")
expect_code("경로 파라미터 미선언", 'route GET "/u/{id}" public:\n    return "x"\n', "E303")
expect_code("타입 없는 라우트 파라미터", 'route GET "/u" (q) public:\n    return q\n', "E303")
expect_code("중복 라우트", 'route GET "/a" public:\n    return "1"\nroute GET "/a" public:\n    return "2"\n', "E304")
expect_code("<script> 안 보간", 'let v = "x"\nlet h = html"<script>var a = {v}</script>"\n', "E401")
expect_code("onclick 속성 보간", 'let v = "x"\nlet h = html"<b onclick=\\"{v}\\">x</b>"\n', "E401")
expect_code("따옴표 없는 속성 보간", 'let v = "x"\nlet h = html"<a href={v}>x</a>"\n', "E401")
expect_code("let 재할당", 'let a = 1\na = 2\n', "E102")
expect_code("오타 (did-you-mean)", 'let count = 1\nprint(cuont)\n', "E101")
expect_code("파이썬 예약어를 이름으로", 'let class = 1\n', "E104")
expect_code("unsafe_html 사용 경고", 'let h = unsafe_html("<b>x</b>")\n', "W301")
expect_code("인증 없는 공개 쓰기 경고", 'route POST "/x" public:\n    return "ok"\n', "W303")

# did-you-mean 힌트가 실제로 생성되는지
d = project('let count = 1\nprint(cuont)\n')
app, diags = build_app(d)
case("[컴파일] 오류에 수정 힌트 포함 (AI 자기수정용)", any(x.hint and "count" in x.hint for x in diags),
     diags[0].to_dict() if diags else "")
shutil.rmtree(d)


# ================================================================ 2) 런타임 차단
def run_fn(src, toml, fn_name, *args):
    d = project(src, toml)
    app, diags = build_app(d)
    errs = [x for x in diags if x.severity == "error"]
    assert not errs, [e.render(app.sources) for e in errs]
    app.access_log = False
    app.load()
    return app, d


SRC = '''
use std.db
use std.http
use std.env
use std.fs

fn raw_sql():
    return db.all("SELECT 1")

fn ssrf_metadata():
    return http.get("http://169.254.169.254/latest/meta-data/")

fn ssrf_loopback():
    return http.get("https://localhost:9999/")

fn ssrf_trick_host():
    return http.get("https://0x7f.0.0.1/")

fn not_allowed_host():
    return http.get("https://evil.example.com/")

fn env_undeclared():
    return env.get("PATH")

fn catch_security():
    try:
        return fs.read("/etc/passwd")
    catch e:
        return "삼켜짐"

fn mutate():
    let t = Item(name="a")
    t.name = "b"

fn open_redirect():
    return redirect("https://evil.example/")

fn html_as_str(x: Str):
    return respond(200, x, content_type="text/html")

fn secret_text():
    let s = env.secret("TOKEN")
    return "토큰={s}"

type Item:
    name: Str

type Strict:
    title: Str
    tags: List[Str] = []

route POST "/strict" (body: Strict) public:
    return body

route GET "/boom" public:
    let xs = [1, 2]
    return xs[10]
'''
TOML = '''[permissions]
db = ["sqlite::memory:"]
net = ["localhost:9999", "api.example.com"]
env = ["TOKEN"]
fs_read = ["./data"]
'''
os.environ["TOKEN"] = "super-secret-value"
app, d = run_fn(SRC, TOML, None)
g = {}


def call(name):
    # 생성된 모듈 전역에서 함수 찾기
    import gc
    for obj in gc.get_objects():
        if callable(obj) and getattr(obj, "__name__", None) == name and getattr(obj, "__code__", None) is not None \
                and obj.__code__.co_filename == "<sori-app>":
            return obj
    raise KeyError(name)


def expect_raise(name, fn, exc_types, must_contain=""):
    try:
        fn()
        case(f"[런타임] {name}", False, "예외가 발생하지 않음")
    except BaseException as e:
        ok = isinstance(e, exc_types) and must_contain in str(e)
        case(f"[런타임] {name}", ok, f"{type(e).__name__}: {str(e)[:90]}")


expect_raise("문자열 SQL 거부 (sql 리터럴만 허용)", call("raw_sql"), SecurityError, "sql")
expect_raise("SSRF: 클라우드 메타데이터 주소", call("ssrf_metadata"), SecurityError, "권한")
expect_raise("SSRF: 허용 목록 호스트라도 내부망 IP 면 차단", call("ssrf_loopback"), SecurityError, "내부망")
expect_raise("SSRF: 16진수 IP 트릭 호스트", call("ssrf_trick_host"), SecurityError)
expect_raise("허용되지 않은 외부 호스트", call("not_allowed_host"), SecurityError, "권한")
expect_raise("미선언 환경변수 접근", call("env_undeclared"), SecurityError, "환경변수")
expect_raise("보안 위반은 try/catch 로 삼킬 수 없음", call("catch_security"), SecurityError)
expect_raise("레코드 불변성", call("mutate"), SoriTypeError, "불변")
expect_raise("오픈 리다이렉트 차단", call("open_redirect"), SecurityError, "리다이렉트")
c = TestClient(app)
r = c._do("GET", "/boom")
case("[런타임] 런타임 오류 시 스택트레이스 비노출 (500 + request_id)", r.status == 500 and "Traceback" not in r.text
     and "request_id" in r.text, r.text[:120])
sec = call("secret_text")()
case("[런타임] Secret 은 문자열 보간에서 *** 로 마스킹", "super-secret" not in sec and "***" in sec, sec)
case("[런타임] Secret 은 HTML/JSON 에서도 마스킹",
     "super" not in str(html(("", ""), (Secret("super"),), ("text",))) and "super" not in json_dumps({"k": Secret("super")}))


def post_raw(body, ctype="application/json", extra=None):
    h = {"host": "localhost", "content-type": ctype}
    h.update(extra or {})
    return dispatch(app, "POST", "/strict", h, body, "127.0.0.1")


case("[입력] 정상 입력 통과", post_raw(b'{"title":"a","tags":["x"]}')[0] == 200)
case("[입력] 중복 JSON 키 거부 (해석 충돌)", post_raw(b'{"title":"a","title":"b"}')[0] == 400)
case("[입력] NaN/Infinity 거부", post_raw(b'{"title":"a","n":NaN}')[0] == 400)
case("[입력] 선언 외 필드 거부 (mass assignment)", post_raw(b'{"title":"a","is_admin":true}')[0] == 400)
case("[입력] 과도한 중첩 거부", post_raw(("[" * 100 + "]" * 100).encode())[0] == 400)
case("[입력] 과도하게 긴 목록 거부 (무제한 증가 DoS)", post_raw(json_dumps({"title": "a", "tags": ["x"] * 20000}).encode())[0] == 400)
case("[입력] 타입 불일치 거부", post_raw(b'{"title":123}')[0] == 400)
case("[입력] 압축 본문 거부 (Brotli/gzip 디코더 공격면 제거)",
     post_raw(b"\x8b\x00", extra={"content-encoding": "br"})[0] == 415)
case("[입력] multipart 거부 (파서 공격면 제거)", post_raw(b"--x", ctype="multipart/form-data; boundary=x")[0] == 400)
case("[입력] 인코딩된 경로 구분자 거부", dispatch(app, "GET", "/a%2f..%2fetc", {"host": "localhost"}, b"", "1.1.1.1")[0] == 400)
shutil.rmtree(d)

# html 응답에 일반 문자열을 넣는 경우 (직접 런타임 호출)
from sori.runtime.web import _to_http  # noqa: E402
from sori.runtime.core import respond  # noqa: E402
try:
    _to_http(respond(200, "<script>x</script>", content_type="text/html"))
    case("[런타임] text/html 응답에 비-Html 문자열 금지", False)
except SecurityError:
    case("[런타임] text/html 응답에 비-Html 문자열 금지", True)


# ================================================================ 3) 실제 HTTP 서버
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


todo = os.path.join(ROOT, "examples", "todo")
shutil.rmtree(os.path.join(todo, "data"), ignore_errors=True)
srv_app, diags = build_app(todo)
srv_app.access_log = False
srv_app.load()
port = free_port()
from sori.runtime.web import serve  # noqa: E402
threading.Thread(target=serve, args=(srv_app, "127.0.0.1", port), daemon=True).start()
for _ in range(50):
    if srv_app.ready:
        break
    time.sleep(0.05)


def raw(req: bytes):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(req)
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    status = int(head.split(" ")[1])
    return status, head, data


st, head, _ = raw(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
case("[HTTP] 정상 요청 200 + 서버 버전 비노출", st == 200 and "Server: sori\r" in head + "\r" and "Python" not in head, head.split("\r\n")[0])
case("[HTTP] CSP/HSTS 대상 보안 헤더", "Content-Security-Policy" in head and "X-Frame-Options: DENY" in head)
st, _, _ = raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
case("[HTTP] 요청 스머글링: Transfer-Encoding 거부", st == 400, st)
st, _, _ = raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\nhello")
case("[HTTP] 요청 스머글링: 중복 Content-Length 거부", st == 400, st)
st, _, _ = raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999\r\n\r\n")
case("[HTTP] 본문 크기 제한 (413, 읽기 전에 차단)", st == 413, st)
st, _, _ = raw(b"POST /todos HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: br\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}")
case("[HTTP] 압축 요청 본문 415", st == 415, st)
st, _, _ = raw(b"GET /api/todos/%2e%2e/x HTTP/1.1\r\nHost: localhost\r\n\r\n")
case("[HTTP] 인코딩된 .. 경로 거부", st == 400, st)
st, head, _ = raw(b"DELETE /api/todos HTTP/1.1\r\nHost: localhost\r\n\r\n")
case("[HTTP] 미지원 메서드 405 + Allow", st == 405 and "Allow:" in head, st)
st, _, body = raw(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
case("[K8s] /healthz", st == 200 and body.endswith(b"ok"))
st, _, body = raw(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
case("[K8s] /readyz", st == 200)
st, _, body = raw(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
case("[K8s] /metrics (Prometheus) 보안 이벤트 집계", st == 200 and b'sori_security_events_total{kind="transfer_encoding"}' in body)

# ================================================================ 결과
w = max(len(n) for n, _, _ in results)
fails = 0
for n, ok, detail in results:
    print(f"{'✓' if ok else '✗'} {n.ljust(w)}" + ("" if ok else f"   ← {detail}"))
    fails += 0 if ok else 1
print(f"\n{'✓' if not fails else '✗'} 보안 테스트 {len(results) - fails}/{len(results)} 통과")
sys.exit(1 if fails else 0)
