"""SORI 언어에서 접근 가능한 '표면' — 컴파일러(정적 타입)와 IR 해석기(런타임 화이트리스트)가 공유한다.

IR 에는 임의 속성 접근이 없다. 해석기는 여기 적힌 이름만 허용하고 나머지는 거부한다(이중 방어).
반환 타입 표기: "Method:<T>" = 호출 가능한 메서드, 그 외 = 값 속성. "<E>" = 컨테이너 원소 타입, "<S>" = 자기 자신 타입.
"""

STR_METHODS = {
    "lower": "Str", "upper": "Str", "strip": "Str", "lstrip": "Str", "rstrip": "Str", "title": "Str",
    "capitalize": "Str", "casefold": "Str", "replace": "Str", "split": "List[Str]", "splitlines": "List[Str]",
    "join": "Str", "startswith": "Bool", "endswith": "Bool", "find": "Int", "count": "Int", "isdigit": "Bool",
    "isalpha": "Bool", "isalnum": "Bool", "zfill": "Str", "removeprefix": "Str", "removesuffix": "Str",
}
LIST_METHODS = {
    "append": "None", "extend": "None", "pop": "<E>", "insert": "None", "remove": "None", "index": "Int",
    "count": "Int", "reverse": "None", "sort": "None", "copy": "<S>", "clear": "None",
}
MAP_METHODS = {
    "get": "<E>?", "keys": "List[Str]", "values": "List[<E>]", "items": "List[Dyn]", "pop": "<E>?",
    "update": "None", "setdefault": "<E>", "copy": "<S>", "clear": "None",
}
RECORD_METHODS = {"copy": "<S>", "to_json": "Map[Json]"}
REQUEST_SURFACE = {
    "method": "Str", "path": "Str", "ip": "Str", "id": "Str",
    "header": "Method:Str?", "query": "Method:Str?", "cookie": "Method:Str?", "json": "Method:Json",
    "form": "Method:Map[Dyn]",
}
HTTP_RESPONSE_SURFACE = {"status": "Int", "headers": "Map[Str]", "text": "Str", "ok": "Bool", "json": "Method:Dyn"}
CLIENT_RESPONSE_SURFACE = {"status": "Int", "headers": "Map[Str]", "text": "Str", "json": "Method:Dyn",
                           "header": "Method:Str?"}
ERROR_SURFACE = {"message": "Str", "code": "Str", "kind": "Str"}
SECRET_SURFACE = {"reveal": "Method:Str"}
ROW_SURFACE = {"get": "Method:Dyn", "keys": "Method:List[Str]", "to_json": "Method:Map[Json]"}
QUERY_SURFACE = {"text": "Str"}
RESPONSE_SURFACE = {"status": "Int"}
TEST_CLIENT_SURFACE = {m: "Method:ClientResponse" for m in ("get", "post", "put", "patch", "delete")}

# 표준 모듈: 메서드 → 정적 반환 타입 (특수 규칙은 컴파일러가 처리)
STD_METHODS = {
    "db": {"exec": "Row", "all": "List[Row]", "one": "Row?"},
    "http": {"get": "HttpResponse", "post": "HttpResponse", "request": "HttpResponse"},
    "fs": {"read": "Str", "write": "Bool", "exists": "Bool", "list": "List[Str]"},
    "env": {"get": "Str?", "secret": "Secret", "has": "Bool"},
    "ai": {"ask": "Str", "classify": "Str", "extract": "Dyn"},
    "json": {"parse": "Json", "stringify": "Str"},
    "time": {"now": "Str", "ms": "Float", "sleep": "None"},
    "log": {"info": "None", "warn": "None", "error": "None"},
    "crypto": {"hash_password": "Str", "verify_password": "Bool", "token": "Str", "sha256": "Str", "uuid": "Str"},
    "worker": {"call": "Map[Json]", "names": "List[Str]"},
}
# 표준 모듈 메서드 → 효과(effect). 권한·정책 분석과 IR 메타데이터에 쓰인다.
STD_EFFECTS = {
    "db": {"*": "db"}, "http": {"*": "net"}, "env": {"*": "env"}, "ai": {"*": "ai"}, "worker": {"*": "worker"},
    "log": {"*": "log"}, "time": {"*": "time"}, "crypto": {"*": "crypto"}, "json": {},
    "fs": {"read": "fs.read", "exists": "fs.read", "list": "fs.read", "write": "fs.write"},
}

BUILTIN_RET = {
    "print": "None", "len": "Int", "str": "Str", "int": "Int", "float": "Float", "bool": "Bool",
    "range": "List[Int]", "list": "List[Dyn]", "sorted": "<A0>", "reversed": "<A0>", "sum": "Dyn",
    "min": "<E0>", "max": "<E0>", "abs": "<A0>", "round": "Dyn", "enumerate": "List[Dyn]", "zip": "List[Dyn]",
    "any": "Bool", "all": "Bool", "map": "List[Dyn]", "filter": "<A0>", "type_of": "Str", "respond": "Response",
    "redirect": "Response", "unsafe_html": "Html", "error": "Never", "expect": "None",
}

# 파이썬 객체 그래프를 타고 탈출하는 데 쓰이는 이름 — 개발용 'use py' 객체에도 적용
FORBIDDEN_ATTRS = {
    "format", "format_map", "mro", "gi_frame", "gi_code", "f_globals", "f_locals", "f_back", "f_builtins",
    "f_code", "tb_frame", "tb_next", "cr_frame", "ag_frame", "func_globals", "func_code", "im_func", "co_code",
}
