"""sori.toml 정책 검증 — 컴파일러와 런타임이 같은 규칙을 공유한다."""
from urllib.parse import urlsplit

WORKER_HOSTS = {"127.0.0.1", "::1"}
TOKEN_ENV = "SORI_API_TOKEN"
TOKEN_MIN, TOKEN_MAX = 32, 4096


def worker_problems(name, cfg):
    """워커는 같은 파드/호스트의 루프백 고정 주소만 허용 (SORI v0.1 규칙 계승)."""
    out = []
    if not isinstance(cfg, dict):
        return [f"[workers.{name}] 은(는) 테이블이어야 해요"]
    url = cfg.get("url")
    if not isinstance(url, str):
        return [f"[workers.{name}] url 이 필요해요 (예: \"http://127.0.0.1:9010/invoke\")"]
    p = urlsplit(url)
    if p.scheme != "http" or p.hostname not in WORKER_HOSTS:
        out.append(f"워커 '{name}' 주소는 http://127.0.0.1 또는 http://[::1] 루프백만 허용돼요")
    if p.username or p.password or p.query or p.fragment or not p.path.startswith("/"):
        out.append(f"워커 '{name}' 주소에 계정정보/쿼리/프래그먼트를 넣을 수 없고 경로는 '/' 로 시작해야 해요")
    try:
        port = p.port
    except ValueError:
        port = None
    if port is None or not 1024 <= port <= 65535:
        out.append(f"워커 '{name}' 포트는 1024~65535 로 명시해야 해요")
    t = cfg.get("timeout_ms", 1000)
    if not isinstance(t, int) or not 100 <= t <= 5000:
        out.append(f"워커 '{name}' timeout_ms 는 100~5000 이어야 해요")
    cmd = cfg.get("command")
    if cmd is not None and (not isinstance(cmd, list) or not all(isinstance(x, str) for x in cmd)):
        out.append(f"워커 '{name}' command 는 문자열 배열이어야 해요")
    return out


def token_problem(value):
    if not value:
        return f"guard bearer 를 쓰는 라우트가 있는데 {TOKEN_ENV} 가 없어요"
    if not TOKEN_MIN <= len(value) <= TOKEN_MAX or "\n" in value or "\r" in value:
        return f"{TOKEN_ENV} 는 {TOKEN_MIN}~{TOKEN_MAX}자, 줄바꿈 없이 설정해야 해요"
    return None


# ---------------------------------------------------------------- sori.toml 값 형식 (PR #3 2차 리뷰 P1)
# sori.toml 의 값은 Dockerfile·Kubernetes YAML·Compose 같은 생성물에 들어간다. 생성기 쪽에서 따옴표 처리도 하지만,
# 셸/YAML 에서 의미가 있는 문자(공백, ; $ ` " ' 줄바꿈, # 등)는 애초에 받지 않는다 — 경로·이름은 안전한 문자 집합만.
import ipaddress as _ip
import re as _re

SAFE_PATH = _re.compile(r"^[A-Za-z0-9_./-]{1,200}$")
ENV_NAME = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
PKG_NAME = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
WORKER_NAME = _re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_NAME = _re.compile(rf"^(?:\*\.)?{_LABEL}(?:\.{_LABEL})*$")


def safe_path_problem(value, what, relative=False):
    if not isinstance(value, str) or not SAFE_PATH.match(value):
        return f"{what} 경로 {value!r} 는 영문·숫자·_ . / - 만 쓸 수 있어요 (공백·따옴표·셸 문자 금지)"
    if ".." in value.split("/"):
        return f"{what} 경로 {value!r} 에 '..' 를 쓸 수 없어요"
    if relative and value.startswith("/"):
        return f"{what} 경로 {value!r} 는 프로젝트 기준 상대 경로여야 해요"
    return None


def _host_ok(host):
    if HOST_NAME.match(host):
        return True
    try:
        _ip.ip_address(host)
        return True
    except ValueError:
        return False


def net_entry_problem(entry):
    """[permissions] net 항목: host · host:port · http(s)://host[:port] (경로·계정정보·쿼리 금지)."""
    if not isinstance(entry, str) or not entry or any(c.isspace() or c in "\"'`;$#\\" for c in entry):
        return f"net 항목 {entry!r} 형식이 잘못됐어요 (예: \"api.example.com\", \"api.example.com:8443\")"
    e = entry.strip().lower()
    if "://" in e:
        u = urlsplit(e)
        if u.scheme not in ("http", "https") or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
            return f"net 항목 {entry!r} 는 http(s)://호스트[:포트] 만 쓸 수 있어요"
        host = u.hostname or ""
        try:
            port = u.port
        except ValueError:
            return f"net 항목 {entry!r} 의 포트가 잘못됐어요"
    else:
        host, _, p = e.partition(":")
        if p and not p.isdigit():
            return f"net 항목 {entry!r} 의 포트가 잘못됐어요"
        port = int(p) if p else None
    if not _host_ok(host):
        return f"net 항목 {entry!r} 의 호스트 이름이 잘못됐어요"
    if port is not None and not 1 <= port <= 65535:
        return f"net 항목 {entry!r} 의 포트는 1~65535 여야 해요"
    return None


def config_value_problems(config):
    """생성물(Dockerfile/YAML)에 들어가는 sori.toml 값의 형식 검사. 문제 문자열 목록 (빈 목록 = 통과)."""
    out = []
    perms = config.get("permissions", {})
    if not isinstance(perms, dict):
        return ["[permissions] 는 테이블이어야 해요"]

    def strings(key):
        v = perms.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            out.append(f"[permissions] {key} 는 문자열 배열이어야 해요")
            return []
        return v

    for key in ("fs_read", "fs_write"):
        for p in strings(key):
            msg = safe_path_problem(p, key)
            if msg:
                out.append(msg)
    for d in strings("db"):
        if d == "sqlite::memory:":
            continue
        if not d.startswith("sqlite:"):
            out.append(f"db 항목 {d!r}: 지금은 sqlite:<상대 경로> 또는 sqlite::memory: 만 지원해요")
            continue
        msg = safe_path_problem(d[len("sqlite:"):], "db", relative=True)
        if msg:
            out.append(msg)
    for e in strings("env"):
        if not ENV_NAME.match(e):
            out.append(f"env 항목 {e!r} 는 환경변수 이름 형식(영문·숫자·_, 숫자로 시작 불가)이어야 해요")
    for n in strings("net"):
        msg = net_entry_problem(n)
        if msg:
            out.append(msg)
    for h in strings("net_private"):
        if not _host_ok(h.lower()):
            out.append(f"net_private 항목 {h!r} 의 호스트 이름이 잘못됐어요")
    for pkg in strings("python"):
        if not PKG_NAME.match(pkg):
            out.append(f"python 항목 {pkg!r} 는 패키지 이름 형식이어야 해요")
    for name in (config.get("secrets", {}) or {}):
        if not ENV_NAME.match(name):
            out.append(f"[secrets] {name!r} 는 환경변수 이름 형식이어야 해요")
    for name in (config.get("workers", {}) or {}):
        if not WORKER_NAME.match(name):
            out.append(f"[workers.{name!r}] 이름은 영문·숫자·_ - 만 (1~40자)")
    static = config.get("app", {}).get("static")
    if static is not None:
        msg = safe_path_problem(static, "[app] static", relative=True)
        if msg:
            out.append(msg)
    return out
