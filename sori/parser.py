"""SORI 파서: 재귀 하강 + 우선순위 기반 표현식."""
from .diagnostics import SoriError
from .lexer import lex, split_interpolation

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
TIME_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0}
CMP_OPS = {"==", "!=", "<", ">", "<=", ">="}


class Node:
    def __init__(self, kind, line, col, **kw):
        self.kind, self.line, self.col = kind, line, col
        self.__dict__.update(kw)

    def __repr__(self):
        fields = {k: v for k, v in self.__dict__.items() if k not in ("kind", "line", "col")}
        return f"{self.kind}({fields})"


class Parser:
    def __init__(self, toks, file):
        self.toks, self.pos, self.file = toks, 0, file

    # ---------- 토큰 유틸 ----------
    def peek(self, k=0):
        return self.toks[min(self.pos + k, len(self.toks) - 1)]

    def next(self):
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def at(self, kind, value=None, k=0):
        t = self.peek(k)
        return t.kind == kind and (value is None or t.value == value)

    def at_op(self, v, k=0):
        return self.at("OP", v, k)

    def at_kw(self, v, k=0):
        return self.at("KW", v, k)

    def err(self, msg, t=None, hint=None):
        t = t or self.peek()
        return SoriError("E002", msg, self.file, t.line, t.col, hint, length=t.length)

    def expect(self, kind, value=None, what=None, hint=None):
        t = self.peek()
        if t.kind != kind or (value is not None and t.value != value):
            got = {"NEWLINE": "줄바꿈", "EOF": "파일 끝", "INDENT": "들여쓰기", "DEDENT": "내어쓰기"}.get(t.kind, repr(t.value))
            raise self.err(f"{what or repr(value or kind)} 이(가) 와야 하는데 {got} 이(가) 왔어요", t, hint)
        return self.next()

    def skip_newlines(self):
        while self.at("NEWLINE"):
            self.next()

    # ---------- 프로그램 / 문장 ----------
    def parse_program(self):
        stmts = []
        self.skip_newlines()
        while not self.at("EOF"):
            if self.at("INDENT"):
                raise self.err("예상치 못한 들여쓰기예요", hint="최상위 코드는 들여쓰지 않아요")
            stmts.append(self.parse_stmt(top=True))
            self.skip_newlines()
        return stmts

    def parse_block(self):
        self.expect("OP", ":", "':'")
        if not self.at("NEWLINE"):
            st = self.parse_simple_stmt()
            self.expect("NEWLINE", what="줄바꿈")
            return [st]
        self.expect("NEWLINE", what="줄바꿈")
        self.skip_newlines()
        self.expect("INDENT", what="들여쓰기된 블록", hint="':' 다음 줄은 4칸 들여쓰세요")
        body = []
        while not self.at("DEDENT") and not self.at("EOF"):
            body.append(self.parse_stmt())
            self.skip_newlines()
        if self.at("DEDENT"):
            self.next()
        return body

    def parse_stmt(self, top=False):
        t = self.peek()
        if t.kind == "KW":
            v = t.value
            if v == "use":
                return self.parse_use(top)
            if v == "type":
                return self.parse_type(top)
            if v == "fn" and self.at("NAME", k=1):
                return self.parse_fn(top)
            if v == "route":
                return self.parse_route(top)
            if v == "guard":
                return self.parse_guard(top)
            if v == "task":
                return self.parse_task(top)
            if v == "test":
                return self.parse_test(top)
            if v == "if":
                return self.parse_if()
            if v == "for":
                return self.parse_for()
            if v == "while":
                self.next()
                cond = self.parse_expr()
                return Node("While", t.line, t.col, cond=cond, body=self.parse_block())
            if v == "try":
                self.next()
                body = self.parse_block()
                self.skip_newlines()
                c = self.expect("KW", "catch", "'catch'")
                name = self.expect("NAME", what="오류 변수 이름").value
                return Node("Try", t.line, t.col, body=body, name=name, handler=self.parse_block(), cline=c.line, ccol=c.col)
        st = self.parse_simple_stmt()
        self.expect("NEWLINE", what="줄바꿈")
        return st

    def parse_simple_stmt(self):
        t = self.peek()
        if t.kind == "KW":
            if t.value in ("let", "var"):
                self.next()
                name_t = self.expect("NAME", what="변수 이름")
                typ = None
                if self.at_op(":"):
                    self.next()
                    typ = self.parse_type_expr()
                self.expect("OP", "=", "'='", hint=f"{t.value} 는 반드시 초기값이 있어야 해요")
                return Node("Let" if t.value == "let" else "Var", t.line, t.col, name=name_t.value,
                            ncol=name_t.col, typ=typ, value=self.parse_expr())
            if t.value == "return":
                self.next()
                val = None if self.at("NEWLINE") else self.parse_expr()
                return Node("Return", t.line, t.col, value=val)
            if t.value in ("break", "continue", "pass"):
                self.next()
                return Node(t.value.capitalize(), t.line, t.col)
            if t.value in ("use", "type", "route", "guard", "task", "test") or (t.value == "fn" and self.at("NAME", k=1)):
                raise self.err(f"'{t.value}' 선언은 파일 최상위에서만 할 수 있어요")
            if t.value in ("if", "for", "while", "try"):
                raise self.err(f"'{t.value}' 블록은 한 줄 블록 안에 쓸 수 없어요")
        expr = self.parse_expr()
        if self.at("OP") and self.peek().value in ("=", "+=", "-=", "*=", "/="):
            op = self.next().value
            if expr.kind not in ("Name", "Attr", "Index"):
                raise self.err("여기에는 값을 대입할 수 없어요", t)
            return Node("Assign", t.line, t.col, target=expr, op=op, value=self.parse_expr())
        return Node("ExprStmt", t.line, t.col, expr=expr)

    def parse_if(self):
        t = self.next()
        branches = [(self.parse_expr(), self.parse_block())]
        orelse = None
        while True:
            save = self.pos
            self.skip_newlines()
            if self.at_kw("elif"):
                self.next()
                branches.append((self.parse_expr(), self.parse_block()))
                continue
            if self.at_kw("else"):
                self.next()
                orelse = self.parse_block()
            else:
                self.pos = save
            break
        return Node("If", t.line, t.col, branches=branches, orelse=orelse)

    def parse_for(self):
        t = self.next()
        names = [self.expect("NAME", what="반복 변수 이름").value]
        if self.at_op(","):
            self.next()
            names.append(self.expect("NAME", what="두 번째 반복 변수").value)
        self.expect("KW", "in", "'in'")
        it = self.parse_expr()
        return Node("For", t.line, t.col, names=names, iter=it, body=self.parse_block())

    # ---------- 선언 ----------
    def _require_top(self, top, t):
        if not top:
            raise self.err(f"'{t.value}' 선언은 파일 최상위에서만 할 수 있어요", t)

    def parse_use(self, top):
        t = self.next()
        self._require_top(top, t)
        is_py = False
        if self.at("NAME", "py"):
            self.next()
            is_py = True
        first = self.expect("NAME", what="모듈 이름")
        parts = [first.value]
        while self.at_op("."):
            self.next()
            parts.append(self.expect("NAME", what="모듈 이름").value)
        alias = None
        if self.at("NAME", "as"):
            self.next()
            alias = self.expect("NAME", what="별칭").value
        self.expect("NEWLINE", what="줄바꿈")
        return Node("Use", t.line, t.col, py=is_py, path=".".join(parts), alias=alias, ncol=first.col)

    def parse_type_expr(self):
        t = self.expect("NAME", what="타입 이름")
        args = []
        if self.at_op("["):
            self.next()
            args.append(self.parse_type_expr())
            while self.at_op(","):
                self.next()
                args.append(self.parse_type_expr())
            self.expect("OP", "]", "']'")
        bounds = None
        if self.at_op("("):  # Str(1, 80) / Int(-10, 10) / List[T](0, 50) — 입력 범위(SORI v0.1 계승)
            self.next()
            lo = self._signed_num()
            self.expect("OP", ",", "','", hint="범위는 (최소, 최대) 형식이에요")
            hi = self._signed_num()
            self.expect("OP", ")", "')'")
            bounds = (lo, hi)
        optional = False
        if self.at_op("?"):  # Str? = 값이 없을 수도 있음(none 허용). 기본은 none 불가
            self.next()
            optional = True
        return Node("TypeRef", t.line, t.col, name=t.value, args=args, optional=optional, bounds=bounds)

    def _signed_num(self):
        neg = False
        if self.at_op("-"):
            self.next()
            neg = True
        v = self.expect("NUM", what="숫자").value
        return -v if neg else v

    def parse_type(self, top):
        t = self.next()
        self._require_top(top, t)
        name = self.expect("NAME", what="타입 이름")
        self.expect("OP", ":", "':'")
        self.expect("NEWLINE", what="줄바꿈")
        self.skip_newlines()
        self.expect("INDENT", what="필드 목록", hint="필드는 '이름: 타입' 형식으로 들여써서 적어요")
        fields, doc = [], None
        while not self.at("DEDENT") and not self.at("EOF"):
            if self.at("STR") and not fields and doc is None:
                doc = self.next().value
                self.expect("NEWLINE", what="줄바꿈")
                self.skip_newlines()
                continue
            fname = self.expect("NAME", what="필드 이름")
            self.expect("OP", ":", "':'", hint="필드는 '이름: 타입' 형식이에요")
            ftype = self.parse_type_expr()
            default = None
            if self.at_op("="):
                self.next()
                default = self.parse_expr()
            fields.append(Node("Field", fname.line, fname.col, name=fname.value, typ=ftype, default=default))
            self.expect("NEWLINE", what="줄바꿈")
            self.skip_newlines()
        if self.at("DEDENT"):
            self.next()
        return Node("TypeDecl", t.line, t.col, name=name.value, fields=fields, doc=doc, ncol=name.col)

    def parse_params(self):
        self.expect("OP", "(", "'('")
        params = []
        while not self.at_op(")"):
            p = self.expect("NAME", what="파라미터 이름")
            typ = default = None
            if self.at_op(":"):
                self.next()
                typ = self.parse_type_expr()
            if self.at_op("="):
                self.next()
                default = self.parse_expr()
            params.append(Node("Param", p.line, p.col, name=p.value, typ=typ, default=default))
            if not self.at_op(")"):
                self.expect("OP", ",", "',' 또는 ')'")
        self.next()
        return params

    def _doc_of(self, body):
        if body and body[0].kind == "ExprStmt" and body[0].expr.kind == "Str" and body[0].expr.tag == "":
            parts = body[0].expr.parts
            if len(parts) == 1 and parts[0][0] == "lit":
                return parts[0][1].strip(), body[1:]
        return None, body

    def parse_fn(self, top):
        t = self.next()
        self._require_top(top, t)
        name = self.expect("NAME", what="함수 이름")
        params = self.parse_params()
        ret = None
        if self.at_op("->"):
            self.next()
            ret = self.parse_type_expr()
        doc, body = self._doc_of(self.parse_block())
        return Node("FnDecl", t.line, t.col, name=name.value, params=params, ret=ret, body=body, doc=doc, ncol=name.col)

    def parse_route(self, top):
        t = self.next()
        self._require_top(top, t)
        m = self.expect("NAME", what="HTTP 메서드 (GET/POST/PUT/PATCH/DELETE)")
        if m.value not in HTTP_METHODS:
            raise self.err(f"'{m.value}' 는 지원하지 않는 HTTP 메서드예요", m, "GET, POST, PUT, PATCH, DELETE 중 하나")
        path_t = self.expect("STR", what="경로 문자열 (예: \"/users/{id}\")")
        if path_t.tag:
            raise self.err("경로에는 태그 문자열을 쓸 수 없어요", path_t)
        params = self.parse_params() if self.at_op("(") else []
        access = None
        if self.at("NAME", "public"):
            self.next()
            access = ("public", None)
        elif self.at_kw("guard"):
            g = self.next()
            gname = self.expect("NAME", what="guard 이름")
            access = ("guard", gname.value, gname.line, gname.col)
        doc, body = self._doc_of(self.parse_block())
        return Node("RouteDecl", t.line, t.col, method=m.value, path=path_t.value, params=params, access=access,
                    body=body, doc=doc, pline=path_t.line, pcol=path_t.col)

    def parse_guard(self, top):
        t = self.next()
        self._require_top(top, t)
        name = self.expect("NAME", what="guard 이름")
        params = self.parse_params()
        doc, body = self._doc_of(self.parse_block())
        return Node("GuardDecl", t.line, t.col, name=name.value, params=params, body=body, doc=doc, ncol=name.col)

    def parse_task(self, top):
        t = self.next()
        self._require_top(top, t)
        name = self.expect("NAME", what="task 이름")
        if not self.at("NAME", "every"):
            raise self.err("task 이름 뒤에는 'every <숫자> <ms|s|m>' 가 와야 해요")
        self.next()
        num = self.expect("NUM", what="주기 숫자")
        unit = self.expect("NAME", what="시간 단위 (ms, s, m)")
        if unit.value not in TIME_UNITS:
            raise self.err(f"'{unit.value}' 는 시간 단위가 아니에요", unit, "ms, s, m 중 하나")
        period = num.value * TIME_UNITS[unit.value]
        doc, body = self._doc_of(self.parse_block())
        return Node("TaskDecl", t.line, t.col, name=name.value, period=period, body=body, doc=doc)

    def parse_test(self, top):
        t = self.next()
        self._require_top(top, t)
        name = self.expect("STR", what="테스트 이름 문자열")
        return Node("TestDecl", t.line, t.col, name=name.value, body=self.parse_block())

    # ---------- 표현식 ----------
    def parse_expr(self):
        if self.at_kw("fn") and self.at_op("(", k=1):
            t = self.next()
            params = self.parse_params()
            self.expect("OP", "=>", "'=>'", hint="람다는 fn(x) => 식 형태예요")
            return Node("Lambda", t.line, t.col, params=params, body=self.parse_expr())
        e = self.parse_or()
        if self.at_kw("if"):
            t = self.next()
            cond = self.parse_or()
            self.expect("KW", "else", "'else'", hint="조건식은 'A if 조건 else B' 형태예요")
            return Node("IfExp", t.line, t.col, then=e, cond=cond, orelse=self.parse_expr())
        return e

    def parse_or(self):
        e = self.parse_and()
        while self.at_kw("or"):
            t = self.next()
            e = Node("BoolOp", t.line, t.col, op="or", left=e, right=self.parse_and())
        return e

    def parse_and(self):
        e = self.parse_not()
        while self.at_kw("and"):
            t = self.next()
            e = Node("BoolOp", t.line, t.col, op="and", left=e, right=self.parse_not())
        return e

    def parse_not(self):
        if self.at_kw("not"):
            t = self.next()
            return Node("Not", t.line, t.col, operand=self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        left = self.parse_add()
        ops, rights = [], []
        while True:
            t = self.peek()
            if t.kind == "OP" and t.value in CMP_OPS:
                self.next()
                ops.append(t.value)
            elif self.at_kw("in"):
                self.next()
                ops.append("in")
            elif self.at_kw("not") and self.at_kw("in", k=1):
                self.next()
                self.next()
                ops.append("not in")
            else:
                break
            rights.append(self.parse_add())
        if ops:
            return Node("Compare", left.line, left.col, left=left, ops=ops, rights=rights)
        return left

    def parse_add(self):
        e = self.parse_mul()
        while self.at("OP") and self.peek().value in ("+", "-"):
            t = self.next()
            e = Node("BinOp", t.line, t.col, op=t.value, left=e, right=self.parse_mul())
        return e

    def parse_mul(self):
        e = self.parse_unary()
        while self.at("OP") and self.peek().value in ("*", "/", "//", "%"):
            t = self.next()
            e = Node("BinOp", t.line, t.col, op=t.value, left=e, right=self.parse_unary())
        return e

    def parse_unary(self):
        if self.at("OP") and self.peek().value in ("-", "+"):
            t = self.next()
            return Node("Unary", t.line, t.col, op=t.value, operand=self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self):
        e = self.parse_atom()
        while True:
            if self.at_op("("):
                t = self.next()
                args, kwargs = [], []
                while not self.at_op(")"):
                    if self.at("NAME") and self.at_op("=", k=1):
                        k = self.next()
                        self.next()
                        kwargs.append((k.value, self.parse_expr(), k.line, k.col))
                    else:
                        if kwargs:
                            raise self.err("이름 붙인 인자 뒤에 위치 인자를 쓸 수 없어요")
                        args.append(self.parse_expr())
                    if not self.at_op(")"):
                        self.expect("OP", ",", "',' 또는 ')'")
                self.next()
                e = Node("Call", t.line, t.col, func=e, args=args, kwargs=kwargs)
            elif self.at_op("."):
                self.next()
                name = self.peek()
                if name.kind not in ("NAME", "KW"):
                    raise self.err("'.' 뒤에는 속성 이름이 와야 해요", name)
                self.next()
                e = Node("Attr", name.line, name.col, obj=e, name=name.value, length=name.length)
            elif self.at_op("["):
                t = self.next()
                lo = hi = None
                is_slice = False
                if not self.at_op(":"):
                    lo = self.parse_expr()
                if self.at_op(":"):
                    self.next()
                    is_slice = True
                    if not self.at_op("]"):
                        hi = self.parse_expr()
                self.expect("OP", "]", "']'")
                e = Node("Index", t.line, t.col, obj=e, index=lo, hi=hi, slice=is_slice)
            else:
                return e

    def parse_atom(self):
        t = self.peek()
        if t.kind == "NUM":
            self.next()
            return Node("Num", t.line, t.col, value=t.value)
        if t.kind == "STR":
            self.next()
            parts = split_interpolation(t, self.file)
            out = []
            for p in parts:
                if p[0] == "lit":
                    out.append(p)
                else:
                    sub = lex(p[1], self.file, line_offset=p[2] - 1, col_offset=p[3] - 1, expr_mode=True)
                    sp = Parser(sub, self.file)
                    ex = sp.parse_expr()
                    if not sp.at("EOF"):
                        raise sp.err("보간 안의 식이 끝나지 않았어요")
                    out.append(("expr", ex))
            return Node("Str", t.line, t.col, tag=t.tag, parts=out, length=t.length)
        if t.kind == "KW":
            if t.value in ("true", "false", "none"):
                self.next()
                return Node("Const", t.line, t.col, value={"true": True, "false": False, "none": None}[t.value])
        if t.kind == "NAME":
            self.next()
            return Node("Name", t.line, t.col, id=t.value, length=t.length)
        if self.at_op("("):
            self.next()
            e = self.parse_expr()
            self.expect("OP", ")", "')'")
            return e
        if self.at_op("["):
            self.next()
            items = []
            while not self.at_op("]"):
                items.append(self.parse_expr())
                if not self.at_op("]"):
                    self.expect("OP", ",", "',' 또는 ']'")
            self.next()
            return Node("List", t.line, t.col, items=items)
        if self.at_op("{"):
            self.next()
            pairs = []
            while not self.at_op("}"):
                if self.at("NAME") and self.at_op(":", k=1):
                    k = self.next()
                    key = Node("Str", k.line, k.col, tag="", parts=[("lit", k.value)])
                elif self.at_op("["):
                    self.next()
                    key = self.parse_expr()
                    self.expect("OP", "]", "']'")
                else:
                    key = self.parse_expr()
                self.expect("OP", ":", "':'")
                pairs.append((key, self.parse_expr()))
                if not self.at_op("}"):
                    self.expect("OP", ",", "',' 또는 '}'")
            self.next()
            return Node("Map", t.line, t.col, pairs=pairs)
        if t.kind in ("NEWLINE", "EOF"):
            raise self.err("식이 와야 하는데 줄이 끝났어요", t)
        raise self.err(f"여기에 {t.value!r} 은(는) 올 수 없어요", t)


def parse(src, file="<sori>"):
    return Parser(lex(src, file), file).parse_program()
