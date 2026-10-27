# SORI 개발 마일스톤 — 검증 가능한 단계 중심

작성일: 2026-10-27. 기간은 참고 목표치이며, 커밋과 테스트를 통과해야만 완료 표시한다.

| ID | 범위 | 완료 기준 | 상태 |
|---|---|---|---|
| A0 | DSL/ASGI API, worker, 컨테이너 샘플 | 기본 동작 및 보안 테스트 | 완료(v0.1) |
| B1 | typed IR, 정적 타입 검사, OpenAPI, 개발 CLI | 유효/악성 샘플 테스트·CI 및 산출물 검증 | 코드 구현/로컬 29 tests 통과 (PR 검토 대상) |
| B1.5 | Ara 통합: IR 중심 범용 코어 (0.3.0a1) | Ara 프런트엔드 + Typed IR v2 + exec 없는 Python Backend, B1 29 tests 무수정 통과, 보안 회귀·마이그레이션 동등성·백엔드 동등성 테스트, CI | 코드 구현/로컬 96 tests 통과 (PR 검토 대상, CI 미실행) |
| B2 | Rust runtime proof of concept | ~~v1~~ **v2** IR 일부를 Rust에서 파싱/실행, 동등성 테스트, 벤치마크 | 수직 슬라이스 구현(실험): 벡터 20건 Python 과 일치. 벤치마크·서버화 미착수 — `docs/B2_RUST_PLAN.ko.md` |
| B3 | LSP, formatter, effects/permission 분석 | 문법 에러 위치, 권한 진단, IDE 테스트 | 부분: effect/권한 분석 기초·JSON 진단(줄·열·힌트)은 B1.5 에 포함. LSP·formatter 미착수 |
| B4 | SBOM, 잠금, SCA, fuzz/CI 보안 | 재현 가능 빌드, 의존성 정책, 퍼징 크래시 0 | 미착수 |
| B5 | API 비교/고객 인터뷰 | FastAPI/Go/Spring 동일 시나리오 지표 및 3 고객 인터뷰 | 미착수 |
| C | 유료 파일럿, RBAC/ABAC, 감사 로그, IPC 격리 | 실제 사용자 검증, 외부 감사 및 계약 | 미착수 |
| D | 언어·프런트엔드·피지컬 AI 생태계 | 안정성·호환성·안전 분리 검증 | 미착수 |

## B1 수용 범위와 한계

- `sori build`는 타입 검사 통과 이후 JSON IR, manifest, OpenAPI만 출력한다. **네이티브 컴파일이 아니다.**
- `sori dev`는 서버 시작 별칭이며 hot reload는 제공하지 않는다.
- VS Code grammar는 구문 색상 표시만 제공한다. LSP/디버그는 제공하지 않는다.
- B1 정적 타입 검사에서 오류를 거부하지만, 외부 타입이나 일반 함수·임의 반복문의 표현은 아직 지원하지 않는다.
- Runtime과 문법은 향후 기능 확장 시 호환성 변경 가능성이 있다.

## 다음 기술 결정

B2를 시작할 때부터 IR을 Rust 구조체로 내려 실행하는 작은 엔드투엔드 수직 슬라이스(예: GET `/health`, POST `/add`)를 우선 만든다. 그 뒤 Python 런타임과 동일 요청으로 결과·예외를 비교한다. benchmark에서는 실제 하드웨어, 부하 조건, p50/p99 지연, 메모리/CPU, 빌드 시간을 함께 기록한다.