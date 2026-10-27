# SORI 통합 문법 (v0.3.0a1) 요약

상태: 알파. 문법은 바뀔 수 있다. 정확한 동작의 기준은 테스트(`tests/test_unified_*.py`)와 예제(`examples/todo`, `robot`, `secure-api`)다.

## 프로젝트 구조

```text
my-app/
  sori.toml     # 이름·권한·보안·워커·한도 (앱이 할 수 있는 일의 전부)
  app.sori      # 같은 폴더의 .sori 파일은 한 네임스페이스를 공유
```

v0.1 선언형 DSL 파일(첫 줄 `app "..."`)은 B1 경로로 그대로 실행된다. 새 문법으로 옮기려면 `sori migrate` 를 쓴다 (`docs/MIGRATION-0.3.ko.md`).

## 값과 변수

```sori
let 이름 = "세계"          # 불변 (재대입 = 컴파일 오류)
var count = 0              # 가변
let xs: List[Int] = [1, 2, 3]
let m = {name: "a", n: 1}  # Map (키는 식별자 또는 문자열)
let s = "안녕, {이름}"      # 문자열 보간
```

- 한글 식별자를 쓸 수 있다. `_` 로 시작하는 이름과 속성은 금지된다 (내부 객체 탈출 차단).
- `none`, `true`, `false`. Bool 과 숫자는 섞어 계산할 수 없다 (컴파일 오류).

## 타입

`Int`, `Float`, `Str`, `Bool`, `Json`, `Html`, `Secret`, `Any`, `List[T]`, `Map[T]`, `T?`(옵셔널), 사용자 레코드. `sql"..."` 리터럴의 타입은 `Query` 다.

범위: `Int(1, 100)`, `Float(-10, 10)`, `Str(1, 80)` (문자열은 길이). **외부 입력(라우트 파라미터·본문·쿼리)은 범위가 필수**다 (`strict_inputs = true` 기본, 없으면 E305).

```sori
type Todo:
    """설명은 OpenAPI·AI 도구 스키마로 나간다"""
    id: Int
    title: Str(1, 200)
    done: Bool = false
```

레코드는 선언되지 않은 필드를 거부한다 (mass assignment 차단). 정적 타입 검사는 점진적이다. 알 수 있는 타입(리터럴·시그니처·레코드 필드·std 반환 타입)은 컴파일 때 검사하고 (E107/E108/E109), 모르는 값(내부적으로 `Dyn`)은 런타임 경계에서 검사한다.

## 함수·람다·제어문

```sori
fn clip(x: Float, lo: Float, hi: Float) -> Float:
    return lo if x < lo else (hi if x > hi else x)

let doubled = map(xs, fn(x) => x * 2)

for x in xs:
    if x > 10:
        break
while count < 3:
    count += 1
try:
    risky()
catch e:
    log.warn("실패", reason=e.message)
```

## 라우트와 접근 정책

모든 라우트는 접근 정책이 있어야 컴파일된다 (E301).

| 정책 | 의미 | 실패 시 |
|---|---|---|
| `public` | 누구나 | — |
| `guard bearer` | 내장 Bearer 토큰 (`SORI_API_TOKEN`, 32자 이상, 상수 시간 비교) | 401 + `WWW-Authenticate` |
| `guard <이름>` | 사용자 정의 guard 함수 | 403 |

```sori
guard admin(req):
    let key = env.secret("ADMIN_KEY")
    return key and key == req.header("x-admin-key", "")

route GET "/api/todos/{id}" (id: Int(1, 1000000000)) public:
    return db.one(sql"SELECT id, title, done FROM todos WHERE id = {id}", Todo)

route POST "/api/todos" (body: NewTodo) guard admin:
    let r = db.exec(sql"INSERT INTO todos (title) VALUES ({body.title})")
    return respond(201, Todo(id=r.last_id, title=body.title))
```

- 인증은 본문 파싱보다 먼저 한다.
- OpenAPI 는 `guard bearer` 만 bearer 보안으로 표기한다. 사용자 guard 는 `x-sori-access` + 403 으로 표기한다.

## 안전 타입

- `sql"... {값} ..."`: 보간은 항상 바인드 파라미터로 처리된다. 일반 문자열은 `db.*` 에 넘길 수 없다.
- `html"... {값} ..."`: 문맥에 맞게 이스케이프된다 (본문·속성·URL 속성의 `javascript:` 무력화). `<script>`/`<style>`/`on*=` 속의 보간은 컴파일 오류다.
- `Secret`: 출력·로그·JSON 에서 마스킹된다.

## 표준 모듈과 권한·효과

`use std.db | http | fs | env | ai | json | time | log | crypto | worker`. 실제 접근은 `sori.toml [permissions]` 에 적힌 것만 허용된다.

컴파일러는 각 함수·라우트·태스크의 **효과(effects)** 를 호출 그래프를 따라 계산해 IR 에 기록한다. 효과 종류는 db, net, fs.read, fs.write, env, ai, worker, log, time, crypto, py 다.

- public 라우트가 (함수를 거쳐서라도) 워커에 닿으면 E306 이다.
- 함수는 값으로 저장·전달할 수 있다. 다만 효과 분석은 보수적이다: 함수값·람다·맵에서 꺼낸 함수를 부르는 곳은, 값으로 빠져나간 모든 함수와 람다의 효과를 가진 것으로 본다.
- `std` 함수·모듈은 값으로 쓸 수 없다 (`let f = worker.call` → E110). 항상 `worker.call(...)` 처럼 직접 호출한다.
- public 라우트가 AI 를 부르면 W305 경고가 난다.

## 워커 (별도 프로세스 파이썬/ML/ROS 어댑터)

```toml
[workers.risk_model]
url = "http://127.0.0.1:9010/invoke"   # 루프백만 허용
timeout_ms = 1200
command = ["python", "worker.py"]      # compose/k8s 사이드카 생성용
```

```sori
return worker.call("risk_model", body, RiskOut)   # 이름은 고정 문자열, 응답은 RiskOut 으로 검증 (위반 시 502)
```

`use py`(같은 프로세스 파이썬)는 **개발 전용**이다. `[dev] in_process_python = true` 와 `python` 권한이 모두 있어야 컴파일되고, 운영(`SORI_ENV=production`)에서는 기동이 거부된다.

## 주기 작업·테스트

```sori
task control every 20 ms:
    step()

test "토큰 없으면 401":
    expect(client.post("/greet", json={name: "세계"}).status == 401)
```

`task` 는 소프트 실시간이다. 마감 초과와 지터는 `/metrics` 로 보고된다. 긴급 정지·인터록·결정적 실시간 제어에는 쓰지 않는다.

## 진단

`sori check --json` 은 코드·줄·열·한국어 메시지·힌트를 JSON 으로 낸다 (AI 자기수정 루프용). AI 가 생성한 코드라고 해서 권한이 자동으로 늘어나지 않는다. 권한은 사람이 `sori.toml` 에서 준다.
