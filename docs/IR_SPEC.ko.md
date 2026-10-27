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

---

# SORI Typed IR v2 — `sori/ir/v2` (통합 언어, 0.3.0a1)

## 버전 정책

| IR | 대상 | 상태 |
|---|---|---|
| `sori/ir/v1` | v0.1 선언형 DSL (`app "..."` 파일) | **동결.** B1 경로에서 그대로 생성 (`sori ir file.sori`) |
| `sori/ir/v2` | 통합 언어 (sori.toml + .sori) | 실험적. 0.x 동안 하위 호환 보장 없음. 변경 시 `docs/ir-v2.schema.json` 과 테스트를 함께 갱신 |

v1 은 파이썬 `ast` 노드 모양(`literal/input/object/...`)에 맞춰져 있어 변수·함수·반복·예외를 표현할 수 없으므로 v2 를 새로 정의했다.
v1 → v2 변환은 IR 수준이 아니라 **소스 수준**(`sori migrate`)에서 한다.

## 신뢰 경계

- IR 은 **실행 가능한 코드가 아닌 데이터**다. 백엔드는 이 명세의 op 만 실행하고, 모르는 op 는 거부한다.
- `sori.lang.ir.validate()` 와 Rust 로더의 검사는 **구조 검사일 뿐 출처 증명이 아니다.** 서명되지 않은 외부 IR 파일을 신뢰된 코드로 취급하지 않는다.
  - Python Backend: 같은 프로세스에서 방금 컴파일한 IR 만 실행한다.
  - Rust 슬라이스: 실험용 CLI 이며 운영 서버가 아니다.
- 워커 URL·비밀값은 IR 에 넣지 않는다 (워커는 이름·타임아웃만). 실제 바인딩은 배포 설정(sori.toml)에서 한다.

## 최상위 구조

```json
{
  "ir_version": "sori/ir/v2",
  "app": "이름",
  "files": ["main.sori", "models.sori"],
  "source_digest": {"main.sori": "<sha256>"},
  "permissions": {"db": ["sqlite:./data/app.db"]},
  "workers": [{"name": "risk_model", "timeout_ms": 1200}],
  "uses": [{"alias": "db", "module": "std.db", "at": [0, 1, 1]}],
  "types": [{"name": "Todo", "doc": "...", "fields": [{"name": "title", "type": {"k": "Str", "lo": 1, "hi": 200}, "default": null}]}],
  "functions": [{"name": "f", "params": [...], "ret": {"k": "Int"}, "ret_t": "Int", "body": [...], "effects": ["db"]}],
  "guards": [{"name": "admin", "params": [...], "body": [...], "effects": ["env"]}],
  "init": [ /* 최상위 문장, 파일 순서 */ ],
  "routes": [{"method": "POST", "path": "/api/todos",
              "params": [{"name": "body", "source": "body", "type": {"k": "Ref", "name": "NewTodo"}, "default": null}],
              "access": {"kind": "guard", "guard": "admin"},
              "body": [...], "returns": "Response", "effects": ["db", "env", "log"], "doc": "...", "at": [0, 47, 1]}],
  "tasks": [{"name": "control", "period_ms": 20.0, "body": [...], "effects": []}],
  "tests": [{"name": "...", "body": [...]}]
}
```

- `at`: `[파일 인덱스, 줄, 열]` — 런타임 오류를 소스 위치로 매핑한다.
- `access.kind`: `public` | `bearer` | `guard` | `deny`
- `params[].source`: `path` | `query` | `body` | `req`
- `effects`: `db` `net` `fs.read` `fs.write` `env` `ai` `worker` `log` `time` `crypto` `py`
  - 함수 호출 그래프로 전이된다.
  - guard 의 효과는 라우트에 포함된다.

## 런타임 타입 (`type`)

`{"k": K, ...}` 형태다.

- K: `Int` `Float` `Str` `Bool` `Json` `Html` `Secret` `Any` `List`(`of`) `Map`(`of`) `Opt`(`of`) `Ref`(`name`)
- 범위: `lo`/`hi`
  - Str·Secret 은 길이(코드 포인트)
  - List 는 개수
  - Int·Float 는 값

## 정적 타입 (`t`)

모든 식 노드에 붙는 문자열이다.

- 예: `Int`, `Str?`, `List[Todo]`, `Map[Json]`, `Todo`, `Dyn`
- `Dyn` 은 정적으로 모름 → 런타임 경계 검사에 맡긴다는 뜻이다.
- 백엔드는 `t` 를 신뢰하지 않는다 (실행 시 다시 검사).

## 문장 (`op`)

| op | 필드 | 의미 |
|---|---|---|
| `let` | name, mutable, scope(`local`/`global`), type?, value | 선언 (type 이 있으면 런타임 검사) |
| `assign` | target(`var`/`field`/`index`), o(`=` `+=` `-=` `*=` `/=`), value | 대입 |
| `expr` | x | 식 문장 |
| `if` | branches `[[cond, body]...]`, else? | |
| `while` | c, body | 반복마다 단계 수 검사 |
| `for` | names(1~2), scope, iter, body | 목록·맵(키)·문자열 |
| `return` / `break` / `continue` / `pass` | x? | |
| `try` | body, name, scope, handler | `Exception` 계열만 잡음. 보안 위반·실행 상한은 잡히지 않음 |

## 식 (`op`)

| op | 필드 | 의미 |
|---|---|---|
| `lit` | v | 스칼라만 (null/bool/int/float/str) |
| `var` | name, scope(`local`/`global`/`builtin`) | |
| `list` / `map` | items / pairs `[[k, v]...]` | 맵 키는 Str |
| `field` | obj, name | **허용 표면(surface)만** — 레코드 필드, 내장 타입 메서드 화이트리스트 (`sori/lang/surface.py`) |
| `std` | obj, module, name | 표준 모듈 메서드 (모듈별 화이트리스트) |
| `index` / `slice` | obj, index / lo, hi | |
| `call` | fn, args, kwargs `[[name, expr]...]` | |
| `binop` | o(`+ - * / // %`), l, r | Bool 산술 금지, `/` 는 항상 Float, `//`·`%` 는 floor 의미론 |
| `unop` / `not` / `logic` | o, x / x / o(`and`/`or`), l, r | logic 은 단락 평가, 피연산자 값을 돌려줌 |
| `compare` | l, ops, rs | 연쇄 비교, 크기 비교는 숫자끼리·문자열끼리만 |
| `cond` | c, then, orelse | |
| `lambda` | params, body | 클로저 |
| `cat` | lits, args | 문자열 보간 (`len(lits) == len(args) + 1`) |
| `sql` | lits, args | 파라미터 바인딩 쿼리 (값은 항상 `?`, 목록은 `IN (?, ?, ...)`) |
| `html` | lits, args, ctx(`text`/`attr`/`url`) | 문맥별 이스케이프, url 문맥은 `javascript:` 등 무력화 |

## 구조 규칙 추가 (PR #3 리뷰 반영)

- `std` 식은 **`call.fn` 자리에만** 올 수 있다. std 함수를 값으로 저장·반환·전달하는 IR 은 검증기가 거부한다.
  - 컴파일러에서는 E110 이다.
  - 런타임은 std 모듈 객체에 대한 `field` 접근을 SecurityError 로 거부한다.
  - 효과(effects) 분석이 호출 위치를 항상 볼 수 있게 하려는 규칙이다.
- 효과 메타데이터(`effects`)는 보수적으로 계산한다. 함수가 값으로 빠져나가면(저장·전달·반환) '빠져나간 함수' 가 된다. 대상을 정적으로 모르는 호출은 빠져나간 함수 전체와 모든 람다의 효과를 받는다.
- 실행 '단계'(max_steps)는 반복문 한 바퀴와 함수·람다 호출 한 번을 센다. 문장 하나하나는 세지 않는다 (클로저 변환 백엔드부터).

## 백엔드 공통 의미론 (요약)

- 정수: Python Backend 는 임의 정밀도, Rust 는 i64 overflow 시 런타임 오류.
  - 입력 범위·상수 제한(±1e12) 안에서는 같다.
- 실수 출력: 정수값이면 `x.0`, 그 외는 최단 왕복 표현.
  - 지수 표기 경계(1e16 이상, 1e-5 이하)는 백엔드 간 표기가 다를 수 있다 — 테스트 벡터 범위 밖.
- 진리값: none/false/0/0.0/빈 문자열·목록·맵 = 거짓.
- 동등 비교는 숫자끼리 값 비교 (`1 == 1.0`).
- 실행 상한
  - Python: 요청당 단계 2,000,000 · 2초 · 호출 깊이 64 (`[limits]`)
  - Rust: 단계 2,000,000

## 공개 API

```bash
sori ir <프로젝트>                       # IR v2 (정규화 JSON)
sori build <프로젝트> --target spec      # typed-ir.json / openapi.json / manifest.json / tools.json
```

- JSON Schema: `docs/ir-v2.schema.json` (`sori.lang.ir.json_schema()` 와 동기화 테스트)
- 구조 검증: `sori.lang.ir.validate(ir)`
- 정규화 직렬화: `sori.lang.ir.canonical(ir)` (같은 소스 → 같은 바이트)
