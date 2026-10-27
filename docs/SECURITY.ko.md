# SORI v0.1 위협 모델과 보안 격차

상태: 초안. 어떠한 독립적인 침투 테스트/외부 보안 감사/형식 검증도 완료하지 않았다.

## 보호하려는 자산

1. 서비스 데이터와 API 자격 증명
2. 호스트/컨테이너 프로세스 권한과 파일시스템
3. AI 워커가 접근 가능한 모델/하드웨어/로봇 명령 채널
4. 빌드 아티팩트와 공급망의 무결성

## 공격자 모델

- 인터넷에서 HTTP 요청을 보내는 외부 사용자
- 스키마를 우회하려는 API 소비자
- 복사한 SORI 소스 파일에 악성 표현을 숨기는 개발자 또는 코드 생성 AI
- 취약한 Python/ASGI/운영체제 의존성 공격자
- 제어권을 잃은 Python 워커 (현재는 *완전 격리 불가*)

## 구현되어 테스트하는 것

| 위협 | v0.1 메커니즘 | 한계 |
|---|---|---|
| 누락된 API 인증 | `public`/`protected` 선언 필수, token 없으면 시작 중단 | 사용자/조직별 ACL, OAuth, RBAC 없음 |
| 입력 기반 RCE | 제한 AST 평가, import/call/exec/eval 지원 안 함 | Python 런타임·종속성의 자체 CVE는 별도 문제 |
| 임의 필드 바인딩 | 선언 입력만 허용하고 타입·범위 확인 | 복잡한 도메인별 인가/BOLA 미지원 |
| JSON 다중 키·비정상 값 | duplicate key/NaN 거부 | HTTP 서버·프록시 레이어의 파싱 불일치는 별도 검증 필요 |
| 기본 출력 XSS | JSON-only, nosniff/CSP 헤더 | 클라이언트가 문자열을 HTML로 렌더하면 별도 XSS 위험 |
| 사용자 입력 SSRF | worker URL은 정적 loopback, 프록시·리다이렉트 금지 | worker 자체가 외부 네트워크로 나갈 수 있음 |
| 과다한 페이로드 | 요청/응답 64KiB 제한 | Rate limit, API gateway, 처리량/DDoS 대응 필요 |
| 컨테이너 탈출 피해 | non-root, read-only FS, cap_drop, seccomp 템플릿 | 배포환경 정책·커널 버그·운영자가 재설정한 권한은 통제 밖 |
| 종속성 공급망 | 런타임 코어는 stdlib 중심 | ASGI 서버, Python 이미지·패키지 잠금과 검증 미구현 |

## 구현 전 필수 체크리스트 (프로덕션 게이트)

- [ ] 핵심 엔진 Rust/WASM capability 모델 구현 및 threat review
- [ ] 종속성 전체 lockfile + image digest + SBOM(CycloneDX/SPDX) + 이미지 서명 검증
- [ ] 주기적인 OS/Python/ASGI 의존성 CVE 검사와 긴급 교체 프로세스
- [ ] OAuth/OIDC + session/token rotation + tenant-scoped ABAC/BOLA 일관 검사
- [ ] mTLS/서비스 신원, ingress TLS, WAF+rate limit, request deadline/cancellation
- [ ] reverse-proxy, percent-encoding, host/header ambiguity, HTTP smuggling 검증
- [ ] worker OS/VM 격리, seccomp/AppArmor, 권한/네트워크/비밀 분리
- [ ] A/I/O 로깅, 분산 tracing, 감사로그 (비밀번호/개인정보 로그 금지)
- [ ] fuzzing/property test, SAST/DAST, 독립 침투테스트, 외부 보안 감사
- [ ] 로봇 safety case, e-stop/watchdog, 물리적 인터락 및 인증 요구 분석
- [ ] 일관된 캐시/SSR 권한 모델, 자동 output escaping, template 테스트
- [ ] 심각도별 취약점 접수/패치/공개 정책 + 재현 가능한 빌드

## 2025~2026 확인한 주요 참고 사례

- Next.js 인증 우회 (CVE-2025-29927): https://github.com/advisories/GHSA-f82v-jwr5-mffw
- React Server Components RCE (CVE-2025-55182): https://nvd.nist.gov/vuln/detail/CVE-2025-55182
- Next.js 2026-10-14 보안 릴리스 (RCE 2종 및 DoS): https://nextjs.org/blog/nextjs-security-update-october-14-2026
- Nuxt 2026 보안 권고: https://github.com/nuxt/nuxt/security/advisories
- Deno permission reference: https://docs.deno.com/runtime/fundamentals/security/
- OWASP Top 10 2025: https://top10.owasp.org/2025/

**주의:** 'SORI는 해당 CVE에 영향받지 않는다'는 주장은 영향을 받는 컴포넌트를 SORI v0.1 직접 의존성으로 사용하지 않는다는 매우 제한된 의미 이상으로 해석할 수 없다. 다른 취약점이 발생하지 않음을 보장하지 않는다.


## v0.2-alpha 추가 및 제약

- SORI 컴파일 단계에서 문자열과 숫자의 잘못된 연산, 비유한/과대 숫자 상수, public worker invocation을 거부.
- OpenAPI 출력은 bearer 형식을 기술하나 생산 환경의 인증 서버, 리소스별 인가나 비밀키 로테이션을 제공하지는 않음.
- Typed IR JSON은 원본 코드를 실행하지 않으나, 독립적인 샌드박스나 실행 엔진 자체가 아님.
- 기존 v0.1에서 public worker 호출을 쓰던 코드는 v0.2에서 컴파일 실패함(고의적인 강화).
- 입력 인증 외에 Rate limiting, tenant isolation, audit logging, dependency SCA 및 운영 비밀키 관리는 구현되지 않음.

---

## v0.3.0a1 (통합 코어) 위협 모델 갱신

상태: 초안. **외부 침투 테스트·퍼징·형식 검증은 여전히 수행하지 않았다.** 아래 표는 "구현했고 로컬 테스트로 확인한 것"과 "아직 검증하지 않은 것"을 구분한다.

### 실행 경계 — 무엇이 보안 경계이고 무엇이 아닌가

| 구성 요소 | 보안 경계인가 | 설명 |
|---|---|---|
| 컴파일 타임 검사 (스코프·타입·권한·라우트 정책·HTML 문맥·`_` 금지) | 아니다 (개발자 실수 방지) | 악의적 개발자를 막는 장치가 아니라 실수를 컴파일 단계에서 걸러내는 장치 |
| IR 해석기 (Python Backend) | **아니다** | `eval`/`exec`/`compile` 없음, 속성 화이트리스트, 실행 상한이 있지만 같은 파이썬 프로세스 안이다. **신뢰할 수 없는 코드를 운영에서 실행하는 샌드박스로 주장하지 않는다** |
| 격리 워커 (`std.worker`) | 부분적 | 별도 프로세스 + 루프백 고정 주소 + 응답 타입 검증. 같은 파드/네트워크 네임스페이스라 **침해된 워커를 루프백이 막아주지는 않는다** → 워커 자체 하드닝(비루트, 읽기전용, drop ALL)과 별도 이그레스 정책 필요 |
| 컨테이너/K8s (`sori k8s`) | 그렇다 (운영자 설정 전제) | 비루트, 읽기전용 루트FS, capabilities drop ALL, seccomp, SA 토큰 미마운트, 권한 기반 NetworkPolicy. 커널·런타임 취약점과 운영자 재설정은 통제 밖 |
| `use py` (같은 프로세스 파이썬) | 아니다 | **개발 전용.** `[dev] in_process_python = true` 가 있어야 컴파일되고, `SORI_ENV=production` 이면 기동 거부 |

### 구현·테스트된 통제 (로컬 96 tests)

| 위협 | 통제 | 테스트 |
|---|---|---|
| 동적 코드 실행 | 런타임 경로에 eval/exec/compile 없음 | AST 스캔 테스트 + CI grep 가드 |
| 변조된 IR | 구조 검증 실패 시 실행 거부 (Python·Rust 모두) | `test_validator_rejects_tampered_ir`, `test_tampered_ir_is_refused_by_interpreter`, Rust 로드 거부 |
| 인증 누락·우회 | 라우트별 정책 필수(E301), 인증을 본문 파싱보다 먼저, bearer 상수 시간 비교, 토큰 32자 미만 기동 거부 | `AuthOrdering`, `FailClosed`, 마이그레이션 동등성 |
| 워커 오남용 | public 라우트에서 워커 호출 금지 (함수 경유 포함, E306), 이름은 고정 문자열, 응답 타입 검증(위반 시 502) | `test_public_route_cannot_reach_worker_even_through_function`, `WorkerV2` |
| 입력 기반 공격 | 범위 필수(E305, 기본값), 엄격 JSON(문자열 숫자·1→true 거부), 중복 키·NaN·깊이·개수·길이 제한, mass assignment 거부 | `test_input_hardening` (12종) |
| SQLi / XSS / CSRF / SSRF / 경로 탈출 / 오픈 리다이렉트 / 비밀값 노출 | Ara 통제 유지 (sql 리터럴, 문맥 이스케이프, Origin 검사, 내부망 차단·IP 고정, realpath, 상대경로만, Secret 마스킹) | `RuntimeSecurity`, 예제 todo 16 tests |
| 요청 스머글링·압축 본문·경로 혼동 | TE 거부, 보안 헤더 중복 거부, Content-Encoding 415, 인코딩된 `/` `..` 거부 (내장 서버·ASGI 공통) | `BuiltinServer`, `AsgiAdapter`, uvicorn E2E |
| 무한 루프·재귀 DoS | 단계 수·호출 깊이·요청 시간 상한, catch 불가 | `test_resource_limits_are_uncatchable`, `test_infinite_loop_request_is_stopped` |
| 운영에서 보안 완화 | `strict_inputs=false`, `use py`, `sori.lock` 누락/불일치 → 운영 기동 거부 | `test_production_refuses_unsafe_configuration` |
| 공급망 | 런타임 의존성 0 (uvicorn 은 선택), Rust 슬라이스 의존성 0, `sori.lock` 소스 해시 | (정적) |

### 아직 검증하지 않은 영역 (프로덕션 게이트 추가 항목)

- [ ] 퍼징: 렉서/파서, JSON 파서(Python·Rust), IR 해석기 차분 퍼징
- [ ] 외부 보안 감사 및 침투 테스트
- [ ] Docker 이미지 실제 빌드·스캔 (이 PR 은 생성물 정적 검증만)
- [ ] IR 서명/출처 증명 (현재 구조 검사만)
- [ ] 멀티 테넌트 인가(BOLA/ABAC), 감사 로그, 비밀키 로테이션
- [ ] 리버스 프록시 앞단과의 헤더/경로 해석 일치 검증
- [ ] Python Backend 의 OS 수준 격리 (seccomp 워커/WASM) — 현재 없음
- [ ] 성능 회귀 기준 (현재 측정치: ADR 0001 §4)

**주의:** 이 문서는 "모든 CVE 를 막는다"고 주장하지 않는다. 런타임(CPython·uvicorn·OS)과 의존 패키지 자체의 취약점은 SORI 가 막을 수 없고, 갱신·재빌드로 대응해야 한다.
