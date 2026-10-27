# SORI × Ara 기능별 중복·충돌 분석과 주 구현 선택

선택 기준(지시서 §4): **보안성 > 테스트 커버리지 > 확장성 > 성능**. "B1 유지"는 v0.1 DSL 경로에서 무수정 유지된다는 뜻이다.

## 1. 컴파일러·언어

| 기능 | SORI B1 | Ara 제안 | 통합 결과 | 근거 |
|---|---|---|---|---|
| 렉서/파서 | 정규식 줄 단위 + `ast.parse` (식) | 자체 렉서·재귀 하강 파서, 들여쓰기 블록, 한글 식별자 | **Ara** (`sori/lang/lexer.py`, `parser.py`). B1 파서는 v0.1 경로에 유지 | 범용 문법 확장 가능, 위치 정보(줄·열) 정확 |
| AST | 파이썬 `ast` 노드 재사용 | 자체 `Node` | **Ara AST** | IR 이 파이썬 `ast` 모양에 묶이지 않음 (B2 Rust 대상) |
| 정적 타입 검사 | 식 단위(+, -, 비교, Bool≠Int) | 없음 (런타임 검사) | **새로 작성** (`sori/lang/types.py`, `compiler.py`): B1 규칙 계승 + 변수·함수 시그니처·레코드 필드·std 반환 타입까지 점진적 추론 | B1 의 강점(정적 거부)을 범용 언어로 확장. 모르는 타입은 Dyn 으로 런타임 경계 검사 |
| 중간 표현 | Typed IR v1 | 없음 (파이썬 소스) | **IR v2 신규** + v1 은 DSL 전용 동결 | v1 은 범용 문장(let/for/try)을 표현할 수 없음 |
| 실행 | AST 화이트리스트 해석 | `compile()`+`exec()` | **IR 해석기 신규** (Python Backend) + **Rust 슬라이스** | B1 원칙(코드 미실행) 준수, 백엔드 교체 가능 |
| 숫자 상수 제한 | ±1e12, 비유한 거부 | 없음 | **B1 규칙 채택** (E002) | 보안 기본값 약화 금지 |
| 진단 | 영어, 줄 번호 | 한국어, 줄·열, 힌트, did-you-mean, `--json` | **Ara** + 새 코드(E107/E108/E109/E305/E306/W305/W306) | AI 자기수정 루프·비전공자 |
| 효과(effect) 분석 | 없음 | 없음 | **신규**: db/net/fs.read/fs.write/env/ai/worker/log/time/crypto/py, 함수 호출 그래프 전이 | 워커 규칙·감사·OpenAPI·IR 메타데이터의 공통 원천 |

## 2. 보안 정책

| 기능 | SORI B1 | Ara 제안 | 통합 결과 | 근거 |
|---|---|---|---|---|
| 라우트 접근 정책 필수 | `public`/`protected` | `public`/`guard` | **둘 다**: `public` / `guard bearer`(= protected) / 사용자 guard. 없으면 E301 | 동등 + 확장 |
| bearer 인증 실패 코드 | 401 | (403) | **401 + WWW-Authenticate** (사용자 guard 는 403) | B1 동작 보존, 의미상 정확 |
| 인증 vs 입력 파싱 순서 | 인증 먼저 | 파싱 먼저 | **인증 먼저** | 미인증 요청이 파서 공격면에 닿지 않음 |
| 입력 범위 | 필수 (`str(1,80)`) | 선택(경고) | **필수가 기본** (`strict_inputs = true`, 운영에서 끌 수 없음) | 지시서 §5.2, B1 수준 유지 |
| JSON 엄격성 | 정확 타입 (bool≠int) | 문자열→숫자 등 변환 허용 | **JSON 경계는 엄격**, 쿼리/폼 문자열만 변환 | B1 보다 약해지지 않게 |
| 중복 키·NaN·깊이 | 거부 | 거부 | 동일 (양쪽 구현 일치) | — |
| 본문 크기 | 64KiB 고정 | 설정(기본 1MiB) | **설정형** (`max_body_kb`), 마이그레이션 시 64 | 유연성 + 이전 동작 보존 |
| 본문 형식 | JSON 만 (415) | JSON+폼 | **설정형** (`body_types`), 미지원 형식 415 | 동등성 보장 |
| 워커 | 루프백 고정, 리다이렉트·프록시 무시, 64KiB, protected 필수 | 동일 규칙 + 응답 타입 검증 | **통합**: 루프백 규칙 + 응답 타입 검증 + **효과 분석으로 public 라우트 호출 금지 (함수 경유 포함)** | B1 규칙을 더 정확히 적용 |
| 같은 프로세스 파이썬 | 없음 | `use py` (권한 필요) | **개발 전용** (`[dev] in_process_python`), 운영 기동 거부 | 지시서 §5.4 |
| SQL/HTML/SSRF/파일/환경변수 | 기능 없음 | 안전 타입·권한 | **Ara** | B1 에는 해당 기능 자체가 없음 |
| 요청 스머글링·압축 본문·경로 혼동 | ASGI 서버 의존 | 자체 검사 | **Ara** (내장 서버·ASGI 어댑터 공통) | — |
| 실행 상한 | 식 깊이 12 | 없음 | **신규**: 단계 수·호출 깊이·요청 시간, catch 불가 | 무한 루프 DoS 차단 |
| 소스 무결성 | 없음 | `sori.lock` | **Ara** + 운영에서 lock 누락도 기동 거부 | 공급망 |

## 3. 도구·CLI

| 명령 | B1 의미 | Ara 의미 | 통합 의미 |
|---|---|---|---|
| `check` | v0.1 파일 검사 | 프로젝트 검사 | v0.1 파일이면 B1, 아니면 통합 검사(`--json` 지원) |
| `ir` | IR v1 | — | v0.1 → v1, 통합 → **v2** |
| `openapi` | v1 기반 | — | v0.1 → B1 생성기, 통합 → **IR v2 기반 생성기** |
| `manifest` | v1 요약 | — | v0.1 → B1, 통합 → `sori/manifest/v2` |
| `build` | JSON 산출물(manifest/IR/OpenAPI) | Docker 컨텍스트+lock | **`--target spec`(기본, B1 호환 + tools.json)** / **`--target oci`** |
| `serve` / `dev` | uvicorn 실행 (dev = serve 별칭) | — | v0.1 → B1 그대로. 통합: `serve` = `run` 별칭, `dev` = 내장 서버·상세 오류 |
| `run` | — | 실행 | 통합 실행 (기본 uvicorn, 기동 거부 검사) |
| `test` | unittest discovery (`--start-directory`) | `.sori` test 블록 | `--start-directory`/`--unittest` 또는 대상에 .sori 가 없으면 unittest (B1 호환), 아니면 test 블록 |
| `new` | `app.sori` (v0.1 문법) | `main.sori` | **`app.sori` + `sori.toml` (v0.3)** — B1 테스트 기대(`app.sori` 생성·check 통과·덮어쓰기 거부) 충족 |
| `tools` / `context` / `audit` / `k8s` / `compose` | — | 있음 | 유지 (tools 는 IR v2 기반으로 재작성) |
| `migrate` | — | — | **신규**: v0.1 → v0.3 변환 + 보고서 |

## 4. 배포

| 항목 | B1 | Ara | 통합 |
|---|---|---|---|
| 루트 Dockerfile·compose·k8s | v0.1 hello 용 수기 템플릿 | — | **무수정 유지** (v0.1 예제용) |
| 앱별 생성 | — | `build`(Dockerfile+lock), `k8s`, `compose` | 유지: 비루트, 읽기전용 FS, drop ALL, seccomp, NetworkPolicy, 워커 사이드카. 기본 서버 uvicorn |
| CI | unittest + B1 산출물 | — | B1 단계 전부 유지 + 3.12/3.13 매트릭스, Rust 빌드, 백엔드 동등성, 예제 test, 마이그레이션 스모크, exec 가드 |

## 5. 의도적으로 바뀐 동작 (호환성 변화)

1. `sori new` 는 v0.3 문법 프로젝트를 만든다 (`app.sori` + `sori.toml`). v0.1 템플릿이 필요하면 v0.1 문법을 직접 작성하거나 이전 버전을 쓴다.
2. 통합 프로젝트 폴더에 v0.1 DSL 파일을 섞으면 컴파일 오류가 난다 (`sori migrate` 안내).
3. Ara 제안 대비 바뀐 점:
   - bearer 실패는 403 → 401
   - JSON 본문은 엄격 타입
   - 범위 없는 입력은 오류
   - `use py` 는 개발 전용
   - 인증을 파싱보다 먼저 수행
4. `/healthz`·`/readyz`·`/metrics` 는 통합 런타임에만 있다 (v0.1 의 `/health` 는 사용자 라우트).
