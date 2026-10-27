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
