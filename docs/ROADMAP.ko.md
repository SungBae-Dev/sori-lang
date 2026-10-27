# SORI 제품화 로드맵 및 사업성 검증

## 단계 A — 현재 제공물 (v0.1)

- 독립 `.sori` 파서/유효성 검사/AST interpreter
- JSON ASGI API, 인증 스키마, 64KiB 제한, Python 워커 호출
- Docker Compose/Kubernetes 샘플, 자동 테스트와 manifest
- 활용 가능: 기술 검증, 고객 인터뷰, 통합 데모
- 활용 불가: 보안 인증이 필요한 프로덕션, 로봇 안전 제어, 범용 애플리케이션 대체

## 단계 B — 검증 가능한 제품 (권장 0~3개월)

### 상태 (2026-10-27)

- **B1 완료 (코드·로컬 테스트 기준)**: 선언식 JSON API의 정적 타입 검사, typed IR v1, OpenAPI 3.1 문서 자동 생성, `sori new/dev/test/build` CLI(네이티브 빌드 아님), 실험적 VS Code highlighting, 해당 기능 테스트 10개 추가(총 29개).
- **미완료**: Rust 런타임, LSP 진단, 정적 효과/리소스 권한 시스템, SBOM/SCA, fuzzing, 공정한 성능/보안 벤치마크 및 외부 감사.
- `docs/MILESTONES.ko.md`를 작업 분해·수용기준의 기준 문서로 사용.


- 3개 타깃 고객의 반복 문제 확인: 산업 AI gateway / 신뢰 가능한 에이전트 도구 API / 내부 업무 자동화
- Rust 기반 HTTP runtime proof of concept + typed IR 고정
- `sori new/dev/test/build`, VS Code highlighting, LSP 진단, 자동 OpenAPI
- 정적 정책 확인: 권한 미표기=컴파일 실패, 취약한 옵션에 린트 경고
- 유지보수 가능한 패치 프로세스, CI fuzzing, SBOM·SCA
- 성능/보안 비교 실험: FastAPI, Go, Spring Boot의 **동일 API/조건** 측정
- 사업 지표: 첫 API 제작 시간, 정책 오류 수, 반복 배포 시간, 지원 비용

## 단계 C — 유료 파일럿 (권장 3~9개월)

- 팀/조직별 인증과 리소스 단위 인가, secrets 관리자 연동
- 신뢰경계가 검증된 Rust↔Python IPC, 워커 격리·관측성
- ORM/SQL with parameter binding + transaction, migration, versioned schema
- 고객 2~3곳에서 운영환경 검증, 공격 시뮬레이션, 외부 감사
- GPU/ONNX/ROS 2 adapter 베타: 비안전필수 inference 중심
- 반복 고객비용과 실제 인력 절감 측정, 지원 계약/관리형 서비스 실험

## 단계 D — 생태계 (권장 9~24개월)

- 완성도 있는 언어 사양, 네이티브 Rust binary/optional WASM isolation
- 웹 UI 렌더링 계층: 서버 UI ↔ 브라우저 권한 경계, SSR + form action
- Svelte/Vue/React 공식 UI adapter (대체 우선 X, 공존 우선)
- 개발자 경험: LSP, debugger, formatter, testing DSL, IDE/AI agent integration
- 내부 템플릿/플러그인 서명 시장, SOC2 등 필요 기준에 따른 감사
- 심화 산업 AI 연동: 산업 프로토콜 게이트웨이, telemetry, fleet management

## 개발 조직·리스크

새 언어 + 런타임 + 프레임워크 + 툴링 + 외부 보안을 동시에 만드는 것은 장기 투자이며, 수개월 만에 PHP/JS/Java/Python의 모든 기능을 대체하기는 어렵다. 소규모 팀이라면 문제 영역 하나에서 **반복 사용 가능한 유료 고객 가치**를 먼저 검증하라. 예상 일정은 목표치로, 확정 예산/일정이 아니다.

## 추천 첫 시장 (가설)

**기업 내부 AI 에이전트 도구 API 및 산업 현장 엣지 추론 API의 접근 통제·감사·배포 문제**에 집중. 주된 이유는 보안 정책과 Python 연동의 가치가 명확하고, 범용 웹 프런트엔드와 직접 경쟁할 필요가 없기 때문이다. 검증 전까지 고객 수요나 수익성은 가설이다.

### 수익 모델 후보

- Core OSS + 팀 정책 대시보드 구독
- 사내망/온프레미스 엔터프라이즈 라이선스
- AI/ROS/산업 장비 인증 커넥터와 SLA 지원
- 관리형 배포/취약점 대응/SBOM 보증 서비스

유료 파일럿 확보 전에는 '새 언어의 우수함'보다 도입·마이그레이션·보안 검증 비용이 가장 큰 위험이다.