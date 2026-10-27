# SORI 설계 문서 — RFC 0001

상태: 연구용 아키텍처 제안 (2026-10-27). 구현 완료 범위와 목표 아키텍처를 구분한다.

## 1. 제품 목표

이 프로젝트는 여러 개발 언어의 추상적 '장점 총합'보다 **Secure-by-default + AI/AX 개발 자동화 + 컨테이너/엣지 일관성**이라는 세 가지 문제를 해결하려는 시도이다. 클라우드 백엔드, AI 업무 자동화, 산업 엣지의 *비안전필수* 애플리케이션에 먼저 집중한다.

### 사용 대상

- 비전공자: 복잡한 프레임워크 설정 없이 선언적 API와 정책을 작성
- 개발자: 디버깅 가능한 타입·권한 정책, 테스트·배포 자동화
- AI 코딩 도구: 기계가 읽을 수 있는 스키마, 예측 가능한 문법과 오류
- 산업 AI: Python/PyTorch/ONNX/ROS 2를 별도 워커에서 호출

### 비목표(초기)

- 모든 CVE의 영구적 제거
- C/C++/Rust/Python의 모든 기능 재현
- 스마트폰/데스크톱/웹 UI를 단일 런타임에서 즉시 완전 구현
- 로봇의 하드 실시간 안전 제어를 Python/LLM에 위임

## 2. 기존 언어/프레임워크 장단점

| 기술 | 장점: 받아올 아이디어 | 단점/제약: 피할 점 | SORI의 결정 |
|---|---|---|---|
| PHP/Laravel | 빠른 웹 개발, 배포 친숙함, convention | 다중 배포 설정 차이·동적 호출면 | 명령 1개로 프로젝트 실행·배포 |
| Node.js/NestJS | 거대한 npm 생태계, 이벤트 기반 I/O, 풀스택 TS | 의존성 복잡도, 과도한 권한 기본 설정 위험 | 명시적 권한과 API 계약 |
| Java/Spring Boot | DI/IoC, 트랜잭션, 모듈성, 운영 도구 | 초심자에게 높은 구성 학습 비용, JVM 운영 부담 | 정책/설정 복잡성 제거, 모듈형 서비스 |
| Next.js/React | SSR/RSC, 라우팅, UI 생태계 | 서버·클라이언트 데이터 경계와 캐시 복잡성 | 서버 능력과 브라우저 능력의 완전한 분리 |
| Nuxt/Vue | 개발 친화적인 풀스택, 파일 기반 라우팅 | 하이브리드 렌더링·미들웨어 경계 관리 | 권한 판단은 최종 핸들러 경로에서 강제 |
| Svelte/SvelteKit | 컴파일 중심, 가벼운 프런트엔드, 높은 DX | 생태계 규모·런타임 경계 별도 검증 필요 | 초경량 UI 어댑터(장기) |
| Electron | 공통 웹 기술로 데스크톱 배포 | Chromium/Node 번들 용량과 보안 업데이트 | 별도 데스크톱 패키징 계층(장기) |
| Python/FastAPI | 직관성, Pydantic 타입 검증, 압도적 AI/ML·ROS 생태계 | CPU 집약/네이티브 확장 안전성·동적 타입 경계 | Python AI worker는 분리, 핵심 API는 엄격한 계약 |
| Rust/Axum | 메모리 안전성, 고성능, 정적 타입 | 소유권/라이프타임의 높은 학습 곡선 | 차후 엔진은 Rust, 최종 사용자 문법은 간단하게 |
| Go | 작은 단일 바이너리, 쉬운 컨테이너 운영 | 특정 고수준 표현에 제약 | 단일 아티팩트와 빠른 시작 경험 |
| Deno | capability-based I/O permission | 모든 라이브러리가 제한에 맞춰 설계된 것은 아님 | 권한은 *기본 거부*로 설계 |

기술별 보안성은 '언어가 안전/불안전'이라는 이분법이 아니라 배포 형태와 해당 버전·기능·운영 방식에 따라 달라진다.

## 3. 최종 목표 아키텍처 — 미구현 부분 포함

```text
    사람 / AI coding agent / 자연어 기반 빌더
                        │
     .sori 소스 + 명시적 타입 + capability policy
                        │
         SORI Parser → Typed AST → Policy Checker
                        │
                Stable SORI IR (planned)
                ┌───────┴─────────┐
                ▼                 ▼
       Rust runtime (planned)   WASM sandbox (planned)
                │                 │
       HTTP/gRPC/Jobs         Restricted plugins
                │                 │
        ABI/IPC + typed protobuf-like contract
                        │
             Python worker / ROS 2 / ONNX
                        │
               Devices / GPU / models

    UI layer (planned): browser client + SSR adapter
    Infra layer: OCI image, Kubernetes, telemetry, SBOM, attestation
```

**현재 v0.1 구현:** SORI 소스 → Python AST의 제한된 노드 구성 → 자체 검증/평가 → Python ASGI API. Python AST는 오직 '구문 분석용'으로 사용한다. `.sori`를 Python 코드로 컴파일하거나 `eval`/`exec`하지 않는다. 별도의 Python worker가 루프백 JSON 프로토콜을 제공한다. Rust/Wasm/SSR/ROS2는 구현하지 않았다.

## 4. 언어 철학

- 인증은 라우트마다 `public` 또는 `protected` 필수. 누락되면 소스 오류.
- 검증되지 않은 자동 데이터 바인딩 없음. 필드는 `input name: str(1,80)` 같은 계약으로 명시.
- `return` 식은 허용된 JSON 표현만 사용. 임의 함수 호출, 동적 import, 파일·네트워크·프로세스 생성 금지.
- HTTP worker 주소는 정적인 루프백 IP와 지정 포트만 허용. 사용자가 입력한 URL로 outbound 요청 불가.
- 반환은 JSON만. HTML·template SSR은 별도의 escaping/트러스트 모델 이후 구현.
- 코드 생성기는 AST/manifest 스키마에 맞는 수정만 수행하게 하고, 런타임 권한 확대는 승인 절차를 둔다(계획).

## 5. AI/AX 프로토콜 설계

- `sori manifest`는 routes/auth/field bounds/worker name을 JSON으로 내보낸다. 비전공자 자연어 인터페이스가 이 스키마에 맞춘 코드를 생성하는 근거 자료로 사용 가능.
- 실제 AI 모델 호출은 신뢰된 Python worker에 위임한다. SORI core가 Python 동적 실행 기능을 암묵적으로 허용하지 않는다.
- 향후: `agent`/`tool`/`approval`/`budget` 선언어 추가, human-in-the-loop 액션, per-agent credential, 호출 비용 제한, 추적 ID, model registry.
- 프롬프트 인젝션을 막는 것은 타입 검증만으로 불가능하므로, 모델이 만든 결과를 외부 시스템의 권한으로 바로 승격하지 않는다.

## 6. 물리 AI 도메인 구분

1. **인지 계층:** 영상, 음성, 센서 추론 = Python/ONNX/Torch 워커.
2. **업무 계층:** 추론 결과의 API/워크플로 = SORI 정책·오케스트레이션.
3. **제어 계층:** ROS2/DDS 기반 노드와 네이티브(C++/Rust) 주기 제어.
4. **안전 계층:** e-stop, HW interlocks, watchdog, failsafe는 별도의 안전 인증 시스템; LLM API로 대체 불가.

ROS2 공식 문서는 Python 클라이언트 `rclpy`를 제공한다: https://docs.ros.org/en/rolling/ROS-Framework/About-Client-Libraries.html

## 7. 배포 경험 (지향점)

최종 목표 명령어는 `sori new`, `sori dev`, `sori test`, `sori build --target oci`, `sori deploy kubernetes`이다. v0.1 **실제 구현 명령어**는 `python -m sori check`, `manifest`, `serve`뿐이다. Dockerfile/Compose/K8s YAML은 제공되나 자동 이미지 빌드·배포 CLI는 미구현.

## 8. 라이선스/생태계

초기 오픈소스 코어(가칭 Apache 2.0), 추후 엔터프라이즈 관리 콘솔, 정책 스캐너, AI 산업 커넥터, 호스팅 관리형 서비스로 수익 모델을 설계할 수 있다. 언어 및 패키지 이름은 상표 조사 전 임시 사용.
