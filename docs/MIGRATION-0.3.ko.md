# v0.1 선언형 DSL → SORI v0.3 통합 문법 마이그레이션

## 요약

```bash
sori migrate examples/hello.sori --out hello-v03   # sori.toml + app.sori 생성, 보고서 출력
sori check hello-v03
SORI_API_TOKEN=<32자 이상> sori run hello-v03      # uvicorn (pip install -e '.[server]')
```

v0.1 파일은 **마이그레이션하지 않아도 계속 동작한다**. CLI 가 첫 줄 `app "..."` 을 보고 B1 경로로 처리한다 (`check/ir/openapi/manifest/build/serve/dev`).

## 변환 규칙

| v0.1 | v0.3 |
|---|---|
| `app "이름"` | `sori.toml` `[app] name = "이름"` |
| `route POST "/p" protected:` | `route POST "/p" (body: PIn) guard bearer:` |
| `route GET "/p" public:` | `route GET "/p" public:` |
| `input name: str(1, 80)` | `type PIn:` 아래 `name: Str(1, 80)` |
| `int(a, b)` / `float(a, b)` / `bool` | `Int(a, b)` / `Float(a, b)` / `Bool` |
| `return {"k": input.x + 1}` | `return {"k": (body.x + 1)}` |
| `True` / `False` / `None` | `true` / `false` / `none` |
| `worker "n" "http://127.0.0.1:9010/invoke" timeout 1200` | `sori.toml` `[workers."n"] url = ...`, `timeout_ms = 1200` + `use std.worker` |
| `invoke "n"` | `return worker.call("n", body)` |
| JSON 전용 본문, 64KiB 제한 | `[security] body_types = ["json"]`, `max_body_kb = 64` |
| `SORI_API_TOKEN` 32자 미만 → 기동 실패 | 동일 (`guard bearer` 사용 시) |

## 동등성 검증

`tests/test_migration_equivalence.py` 가 v0.1 런타임(`sori.runtime.create_app`)과 마이그레이션된 v0.3 앱(ASGI)에 **같은 요청 23개**를 보내 비교한다.

- **같은지 확인하는 것**
  - 상태 코드
  - 200 응답 본문
  - 라우트별 접근 정책(public / protected→bearer)
- **요청 구성**
  - 인증: 토큰 없음, 잘못된 토큰, 중복 Authorization 헤더
  - 입력 범위·타입: 범위 밖, bool→int, 문자열 숫자, 선언 외 필드, 누락
  - 본문 형식: 중복 키, NaN, 64KiB 초과, text/plain
  - 라우팅: 404, 405
  - 실제 워커 호출 3종

## 자동 변환되지 않거나 동작이 다른 부분

| 상황 | 차이 | 대응 |
|---|---|---|
| 입력이 없는 POST 라우트 | v0.1 은 본문이 정확히 `{}` 인지 검사, v0.3 은 본문을 읽지 않음 | 보고서에 `[동작 차이]` 로 표시. 검사가 필요하면 필드가 있는 type 을 선언 |
| 오류 응답 본문 | v0.1 `{"error": "invalid value for name"}`, v0.3 은 한국어 메시지 + `request_id` | 상태 코드는 동일. 메시지 문자열에 의존하는 클라이언트는 수정 필요 |
| 보안 헤더 | v0.1 CSP `default-src 'none'`, v0.3 기본 CSP 는 HTML 앱용 | `[security] csp = "default-src 'none'; frame-ancestors 'none'"` 로 동일하게 설정 가능 |
| 헬스체크 | v0.1 은 사용자 라우트 `/health`, v0.3 은 추가로 `/healthz` `/readyz` `/metrics` 제공 | 기존 `/health` 라우트는 그대로 변환됨 |
| 변환 불가 식 | v0.1 검증기가 허용하는 식은 모두 변환되지만, 실패 시 `[수동 수정 필요]` 와 위치 출력 | 생성 파일에 `error("migration: manual fix required", 500)` 이 들어가므로 배포 전 반드시 수정 |

## 운영 설정 변경 (PR #3 리뷰 반영)

2026-10-27 프로젝트 오너가 아래 변경을 모두 수용했다 (ADR 0001 §6). `--egress cilium` 은 실제 Cilium 검증 전까지 실험 기능이다.

| 이전 | 지금 | 이유 |
|---|---|---|
| `[app] allow_unlocked = true` 면 운영에서 `sori.lock` 없이 기동 | **삭제.** 운영(`SORI_ENV=production`)에서는 lock 이 항상 필요하고, 우회 설정은 없다 | 운영 fail-closed 에 예외를 두지 않음 |
| 운영에서 `--server builtin` 은 경고 후 실행 | **기동 거부 (exit 3).** 운영은 uvicorn 만 쓴다. `sori build --target oci` 이미지는 항상 uvicorn | 내장 서버는 개발 전용 |
| `/metrics` 기본 공개 | **기본 비공개.** `SORI_METRICS_TOKEN`(32자 이상)이 있을 때만 `Authorization: Bearer` 로 응답, 없으면 404 | 내부 지표 노출 방지 |
| `[security] metrics = true/false` | `"token"`(기본) · `"public"` · `"off"`. `true` → `"token"`, `false` → `"off"` 로 읽음 | 공개는 명시적으로만 |
| `sori.lock` 은 .sori·sori.toml·워커 파일만 해시 | 이미지에 들어가는 파일 전부를 해시: `[app] static` 폴더, `[permissions] fs_read` 경로 포함. 해시되지 않은 파일은 이미지에 복사하지 않음 | 정적 리소스 변조 탐지 |
| `sori k8s` 가 `net` 권한이 있으면 NetworkPolicy 에 '모든 목적지 TCP 443' 허용을 넣음 | **넣지 않음.** 기본(`--egress none`)은 클러스터 DNS 만 허용하고 외부 이그레스는 막는다 (kind 실클러스터 CI 로 검증). Cilium 이면 `--egress cilium` 으로 net 권한의 호스트:포트만 여는 CiliumNetworkPolicy 를 추가 — **이 정책은 실제 Cilium 클러스터에서 검증하지 않았으므로 적용 후 허용·차단을 직접 확인** | 표준 NetworkPolicy 는 도메인 단위 허용을 표현할 수 없고, 허용 규칙은 합집합이라 열린 443 이 FQDN 정책을 무력화 |
| sori.toml 값 형식 제한 없음, `fs_read = ["/etc"]` 같은 절대 경로 권한 허용 | 경로(`fs_read`·`fs_write`·`db`·`static`)는 **프로젝트 기준 상대 경로만**, 영문·숫자·`_ . / -` 만, `..` 금지, 프로젝트 밖을 가리키는 심볼릭 링크 금지. env·secrets 는 환경변수 이름 형식, net 은 `호스트[:포트]` 또는 `http(s)://호스트[:포트]`, python 은 패키지 이름 형식, 워커 이름은 영문·숫자·`_ -`. 위반 시 E204 | 값이 Dockerfile·YAML 에 들어가므로 주입 방지 |

`sori k8s` 는 기본(token) 모드에서 `prometheus.io/scrape` 어노테이션을 넣지 않는다. Prometheus Operator 를 쓴다면 ServiceMonitor 의 `bearerTokenSecret` 에 같은 토큰을 지정한다. 공개 스크랩이 꼭 필요하면 `[security] metrics = "public"` 을 쓰고, 네트워크 정책으로 접근을 제한한다.

## 마이그레이션 후 권장 작업

1. `sori audit` 로 권한·효과·접근 정책 확인
2. `sori build --target spec` 로 OpenAPI·IR 확인
3. `sori build --target oci` → `sori k8s` / `sori compose` 로 배포 산출물 생성 (워커 `command` 를 적으면 사이드카 자동 구성)
