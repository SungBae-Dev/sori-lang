# SORI Typed IR v1 — 실험적 명세

IR 버전: `sori/ir/v1` (원본 SORI 언어 버전 및 패키지 버전과 독립).

## 목적과 신뢰 경계

`.sori` AST를 정적 타입 검사하여 기계가 검토할 수 있는 JSON 표현으로 변환한다. **IR은 실행 가능한 바이너리나 샌드박스가 아니며, 무결성 서명/신뢰성 인증을 제공하지 않는다.** IR에는 worker 이름과 타임아웃만 포함하며 worker URL은 제외한다. 실행 시 worker URL 및 기타 환경별 바인딩을 신뢰된 배포 설정에서 별도로 처리하는 설계가 필요하다.

## 스키마 요약

- 최상위: `ir_version`, `app`, `workers`, `routes`
- Route: `method`, `path`, `access` (`public` 또는 `protected`), `inputs`, `action`
- Input: `name`, `type` (`str`, `int`, `float`, `bool`), `minimum`, `maximum`
- Expression: `op`, `type`, 그리고 `members` / `items` / `left` / `right` / `operand` / `value` / `field` 등 op별 필드
- Expression op: `literal`, `input`, `object`, `array`, `add`, `subtract`, `neg`, `equal`, `not_equal`, `greater`, `greater_or_equal`, `less`, `less_or_equal`
- Worker action: `{ "op": "invoke", "worker": "...", "type": "object" }`; 응답 형식은 구체적으로 확정하지 않음.

## 타입 규칙

- `+`: 숫자 + 숫자 또는 문자열 + 문자열.
- `-`, unary `-`: 숫자 전용.
- 순서 비교 `>`, `>=`, `<`, `<=`: 숫자 전용.
- 동등 비교 `==`, `!=`: 타입이 달라도 허용. 런타임에서는 정확히 같은 타입일 때만 `==`가 참.
- `bool`은 `int`가 아니다. 숫자 연산에 사용할 수 없다.
- 비유한 float 또는 ±1e12 범위 밖 상수는 컴파일 실패.
- 오브젝트와 배열은 JSON 구조를 유지하지만 객체의 정확한 스키마는 선언된 표현식과 worker 여부에 따라 달라질 수 있다.

## 공개 API

```bash
sori check examples/hello.sori
sori ir examples/hello.sori
sori openapi examples/hello.sori
sori build examples/hello.sori --out .sori-build
```

`build`는 `typed-ir.json`, `manifest.json`, `openapi.json`만 저장한다. 네이티브 실행 파일이나 WASM 모듈을 생성하지 않는다.

## 다음 버전에서 확정할 사항

오류 코드의 안정화, 리터럴 길이 제약, 표현식 효과 타입, 버전 협상, 모듈·패키지 구조, 기계 검증 가능 JSON Schema, Rust lowering 및 결정적 실행 의미론. 변경 전에는 `sori/ir/v1`의 하위 호환성을 보장하지 않는다.