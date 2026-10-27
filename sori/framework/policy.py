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
