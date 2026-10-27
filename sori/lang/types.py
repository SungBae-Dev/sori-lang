"""정적 타입 표현 (문자열 기반, 점진적 타입).

- 알려진 타입: Int Float Str Bool None Html Secret Query Json Response Request Row HttpResponse ...
- 컨테이너: List[T], Map[T] (키는 항상 Str)
- 선택적: T?  (none 허용)
- 레코드: 선언한 type 이름
- Dyn: 정적으로 알 수 없음 → 런타임 경계 검사에 맡김
"""
DYN = "Dyn"
NEVER = "Never"
NUMERIC = {"Int", "Float"}
SCALARS = {"Int", "Float", "Str", "Bool"}


def opt(t):
    if t in (DYN, NEVER, "None", "Json", "Any") or t.endswith("?"):
        return t
    return t + "?"


def strip(t):
    return t[:-1] if t.endswith("?") else t


def is_opt(t):
    return t.endswith("?") or t in ("None", "Json", "Any", DYN)


def list_of(t):
    return f"List[{t}]"


def map_of(t):
    return f"Map[{t}]"


def inner(t):
    """List[X] / Map[X] → X"""
    t = strip(t)
    if (t.startswith("List[") or t.startswith("Map[")) and t.endswith("]"):
        return t[t.index("[") + 1:-1]
    return DYN


def is_list(t):
    return strip(t).startswith("List[")


def is_map(t):
    return strip(t).startswith("Map[")


def known(t):
    return t not in (DYN, "Any", "Json", NEVER)


def compat(expected, actual):
    """actual 값을 expected 자리에 넣을 수 있는가 (정적으로 '확실히 틀린' 경우만 False)."""
    if expected is None or actual is None:
        return True
    if expected in (DYN, "Any", "Json") or actual in (DYN, NEVER, "Any", "Json"):
        return True
    if actual == "None":
        return is_opt(expected)
    e, a = strip(expected), strip(actual)
    if e == a:
        return True
    if e == "Float" and a == "Int":
        return True
    if (is_list(e) and is_list(a)) or (is_map(e) and is_map(a)):
        return compat(inner(e), inner(a))
    if e.startswith("Lambda:") and a.startswith(("Lambda:", "Fn:")):
        # 호출 가능한 값끼리: 반환 타입이 확실히 다를 때만 거부
        return a.startswith("Fn:") or compat(e[7:], a[7:])
    return False


def join(a, b):
    """조건식/여러 return 의 공통 타입."""
    if a == b:
        return a
    if a == NEVER:
        return b
    if b == NEVER:
        return a
    if a == "None":
        return opt(b)
    if b == "None":
        return opt(a)
    if {strip(a), strip(b)} == NUMERIC:
        return "Float"
    if strip(a) == strip(b):
        return opt(strip(a))
    return DYN
