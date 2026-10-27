# Phase B2 — Rust Backend 계획과 현재 수직 슬라이스

## 현재 상태 (0.3.0a1): **준비 + 실험 슬라이스 구현**. 운영용 아님.

```text
.sori → Lexer → Parser → Typed AST → Typed IR v2 (Python 컴파일러)
                                          │
                                          ├─ Python Backend (sori/framework/interp.py) — 전체 기능
                                          └─ Rust Backend 슬라이스 (runtime-rs/, sori-rt) — 부분 기능
                                                 → JSON 응답 ({"status", "body"})
```

| 항목 | 구현 | 비고 |
|---|---|---|
| 의존성 | **0개 (std 전용)** | 엄격 JSON 파서/직렬화기 직접 구현 (중복 키·NaN 거부, 깊이 제한, 순서 보존) |
| IR 로드 | `sori/ir/v2` 버전 확인, 라우트별 지원 여부 판정 | 지원 밖 기능 → 해당 라우트 **501 + 사유** (조용히 다르게 실행하지 않음) |
| 접근 정책 | public / bearer(상수 시간 비교, 토큰 32자 미만이면 기동 거부) / deny | 사용자 guard 미지원 |
| 입력 | 경로·쿼리(중복 거부)·JSON 본문, 레코드 + 범위 검증, 엄격 JSON | 폼 본문 미지원 |
| 문장 | let, 대입(변수), if/elif/else, while, for, return/break/continue/pass, 식 문장 | try 미지원 |
| 식 | lit, var, list, map, field, index, slice(목록), binop, unop, not, logic, compare, cond, cat, 내장(len/str/abs/min/max/int/float) | sql/html/std/사용자 함수/람다 미지원 |
| 실행 상한 | 단계 2,000,000 | 시간 상한 없음 (CLI 1회 실행) |
| 인터페이스 | CLI: `sori-rt ir.json METHOD PATH [--json BODY] [--auth]`, `--check` | HTTP 리스너 없음 |

## 검증

`tests/test_backends.py`: `tests/vectors/calc` (20개 요청)를 **기대값 · Python Backend · Rust Backend** 3자 비교한다.

- 정수/실수/Bool 타입까지 구분하는 엄격 비교로 전부 일치한다 (로컬, 2026-10-27).
- 슬라이스 밖 프로그램(todo 예제: std.db 사용)은 501 로 거부되는지 확인한다.
- bearer 토큰이 없으면 기동 거부(종료 코드 3)되는지 확인한다.
- 버전이 다르거나 JSON 이 변조된 IR 은 로드 거부되는지 확인한다.
- CI: `cargo build --release --locked` 후 같은 테스트를 실행한다.

## 주장하지 않는 것

- 성능 향상: **측정하지 않았다.** 현재 CLI 는 요청마다 프로세스를 띄우므로 서버 성능과 비교할 수 없다.
- 메모리 안전성 이점: Rust 의 언어 수준 보장 외에 별도 검증(퍼징·감사)을 하지 않았다.
- 의미론 완전 동등성: 벡터 범위 안에서만 확인했다.
  - 알려진 차이: 정수 오버플로(Python 임의 정밀도 vs Rust i64 오류), 지수 표기 실수 문자열화.

## 다음 단계 (제안)

1. **IR 의미론 명세 고정**: `docs/IR_SPEC.ko.md` v2 를 테스트 벡터와 1:1 로 맞추고 벡터 세트 확대 (목표: 연산자·문장·오류 경로별 최소 1개).
2. **HTTP 서버화**: 의존성 정책 결정 필요 (std 만으로 HTTP/1.1 vs hyper/axum). 공급망 검토 + 퍼징 후 도입.
3. **std 모듈 이식 순서**: `json` → `time`/`log` → `crypto` → `worker`(루프백) → `db`(SQLite 바인딩, 의존성 검토) → `http`(SSRF 정책 동일 구현).
4. **사용자 함수·guard·람다**: 호출 프레임·클로저·실행 상한 (호출 깊이) 구현.
5. **동등성 하네스**: 같은 IR 에 무작위 입력을 넣어 두 백엔드 결과를 비교하는 차분 퍼징 (cargo-fuzz + Python 기준 구현).
6. **IR 서명**: `sori build` 산출물에 소스 다이제스트 + 서명 → Rust 로더가 서명 확인 후에만 실행 (현재는 구조 검사만).
7. **성능 측정**: 같은 머신·같은 요청 집합으로 Python Backend / Rust Backend / B1 v0.1 런타임 p50·p99 비교 후 문서화.
   - 기준선 (ADR 0001 §4): Python Backend 는 클로저 변환 후에도 CPU 집약 코드가 네이티브 파이썬보다 2.6~11배 느리다.
   - Rust 백엔드가 이 차이를 줄이는지는 측정 전까지 주장하지 않는다.

## 완료 기준 (B2 를 '구현 완료'로 표시하려면)

- 예제 3개(todo/robot/secure-api)의 모든 라우트가 Rust 에서 지원(501 없음)
- 벡터·차분 퍼징에서 불일치 0
- HTTP 서버 모드 + 보안 헤더·스머글링 방어 테스트 통과
- 의존성 감사(cargo-deny/cargo-audit) 통과, 재현 가능한 빌드
