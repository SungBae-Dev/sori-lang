"""SORI 렉서: 파이썬식 들여쓰기 + 태그 문자열(sql"", html"") + 한글 식별자."""
from .diagnostics import SoriError

KEYWORDS = {
    "use", "type", "fn", "route", "guard", "task", "test", "let", "var", "if", "elif", "else",
    "for", "in", "while", "return", "break", "continue", "pass", "true", "false", "none",
    "and", "or", "not", "try", "catch",
}
# 생성되는 파이썬 코드와 충돌하므로 식별자로 쓸 수 없는 단어
PY_RESERVED = {
    "class", "def", "lambda", "del", "global", "nonlocal", "import", "from", "with", "yield",
    "async", "await", "raise", "assert", "is", "except", "finally", "None", "True", "False",
}
STRING_TAGS = {"sql", "html"}
OPS2 = {"->", "=>", "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=", "//"}
OPS1 = set("()[]{},:.+-*/%<>=?")


class Tok:
    __slots__ = ("kind", "value", "line", "col", "tag", "length", "raw_line", "raw_col")

    def __init__(self, kind, value, line, col, tag="", length=1):
        self.kind, self.value, self.line, self.col, self.tag, self.length = kind, value, line, col, tag, length
        self.raw_line, self.raw_col = line, col  # 문자열 내용 시작 위치(보간 오류 위치 계산용)

    def __repr__(self):
        return f"Tok({self.kind},{self.value!r},{self.line}:{self.col})"


def _is_ident_start(c):
    return c.isalpha() or c == "_"


def _is_ident_char(c):
    return c.isalnum() or c == "_"


def lex(src, file="<sori>", line_offset=0, col_offset=0, expr_mode=False):
    toks = []
    i, n = 0, len(src)
    line, col = 1 + line_offset, 1 + col_offset
    indents = [0]
    depth = 0
    at_line_start = not expr_mode

    def err(msg, l=None, c=None, hint=None, length=1):
        return SoriError("E001", msg, file, l or line, c or col, hint, length=length)

    while i < n:
        c = src[i]
        if at_line_start and depth == 0:
            j, width = i, 0
            while j < n and src[j] in " \t":
                if src[j] == "\t":
                    raise err("탭 문자로 들여쓰기 할 수 없어요", line, width + 1, "스페이스 4칸을 사용하세요")
                width += 1
                j += 1
            if j >= n:
                i = j
                break
            if src[j] == "\n":
                i = j + 1
                line += 1
                col = 1
                continue
            if src[j] == "#":
                while j < n and src[j] != "\n":
                    j += 1
                i = j
                continue
            if width > indents[-1]:
                indents.append(width)
                toks.append(Tok("INDENT", width, line, 1))
            else:
                while width < indents[-1]:
                    indents.pop()
                    toks.append(Tok("DEDENT", width, line, 1))
                if width != indents[-1]:
                    raise err("들여쓰기 깊이가 바깥 블록과 맞지 않아요", line, width + 1, "같은 블록은 같은 칸 수로 들여쓰세요")
            i = j
            col = width + 1
            at_line_start = False
            continue

        if c == "\n":
            if depth == 0 and not expr_mode:
                if toks and toks[-1].kind not in ("NEWLINE", "INDENT", "DEDENT"):
                    toks.append(Tok("NEWLINE", None, line, col))
                at_line_start = True
            i += 1
            line += 1
            col = 1
            continue
        if c in " \t\r":
            i += 1
            col += 1
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "\\" and i + 1 < n and src[i + 1] == "\n":
            i += 2
            line += 1
            col = 1
            continue

        # 숫자
        if c.isdigit():
            j = i
            while j < n and (src[j].isdigit() or src[j] == "_"):
                j += 1
            is_float = False
            if j + 1 < n and src[j] == "." and src[j + 1].isdigit():
                is_float = True
                j += 1
                while j < n and (src[j].isdigit() or src[j] == "_"):
                    j += 1
            if j < n and src[j] in "eE" and j + 1 < n and (src[j + 1].isdigit() or src[j + 1] in "+-"):
                is_float = True
                j += 2
                while j < n and src[j].isdigit():
                    j += 1
            text = src[i:j].replace("_", "")
            toks.append(Tok("NUM", float(text) if is_float else int(text), line, col, length=j - i))
            col += j - i
            i = j
            continue

        # 식별자 / 키워드 / 태그 문자열
        if _is_ident_start(c):
            j = i
            while j < n and _is_ident_char(src[j]):
                j += 1
            word = src[i:j]
            if word in STRING_TAGS and j < n and src[j] == '"':
                tok, i2, line2, col2 = _lex_string(src, j, line, col + (j - i), file, tag=word)
                tok.col = col
                toks.append(tok)
                i, line, col = i2, line2, col2
                continue
            if word in PY_RESERVED:
                raise SoriError("E104", f"'{word}' 은(는) 예약어라 이름으로 쓸 수 없어요", file, line, col,
                               "다른 이름을 쓰세요 (예: " + word + "_value 대신 의미있는 이름)", length=len(word))
            kind = "KW" if word in KEYWORDS else "NAME"
            toks.append(Tok(kind, word, line, col, length=len(word)))
            col += j - i
            i = j
            continue

        if c == '"':
            tok, i, line, col = _lex_string(src, i, line, col, file)
            toks.append(tok)
            continue
        if c == "'":
            raise err("문자열은 큰따옴표(\")만 써요", hint="'abc' 대신 \"abc\"")

        two = src[i:i + 2]
        if two in OPS2:
            toks.append(Tok("OP", two, line, col, length=2))
            i += 2
            col += 2
            continue
        if c in OPS1:
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth < 0:
                    raise err(f"짝이 맞지 않는 '{c}'")
            toks.append(Tok("OP", c, line, col))
            i += 1
            col += 1
            continue
        if c == "!":
            raise err("'!' 대신 'not' 을 쓰세요")
        if c in "&|":
            raise err(f"'{c}' 연산자는 없어요", hint="논리 연산은 and / or 를 쓰세요")
        raise err(f"알 수 없는 문자 '{c}'")

    if depth > 0:
        raise err("괄호가 닫히지 않았어요")
    if not expr_mode:
        if toks and toks[-1].kind not in ("NEWLINE", "DEDENT"):
            toks.append(Tok("NEWLINE", None, line, col))
        while len(indents) > 1:
            indents.pop()
            toks.append(Tok("DEDENT", 0, line, 1))
    toks.append(Tok("EOF", None, line, col))
    return toks


def _lex_string(src, i, line, col, file, tag=""):
    """i 는 여는 따옴표 위치. 원문(이스케이프 미처리) 내용을 돌려준다."""
    n = len(src)
    start_line, start_col = line, col
    triple = src.startswith('"""', i)
    q = 3 if triple else 1
    j = i + q
    content_line, content_col = line, col + q
    cur_line, cur_col = line, col + q
    while True:
        if j >= n:
            raise SoriError("E001", "문자열이 닫히지 않았어요", file, start_line, start_col)
        ch = src[j]
        if ch == "\\":
            j += 2
            cur_col += 2
            continue
        if ch == "\n":
            if not triple:
                raise SoriError("E001", "한 줄 문자열 안에 줄바꿈이 있어요", file, start_line, start_col,
                               '여러 줄은 """ ... """ 를 쓰세요')
            j += 1
            cur_line += 1
            cur_col = 1
            continue
        if triple and src.startswith('"""', j):
            raw = src[i + 3:j]
            j += 3
            cur_col += 3
            break
        if not triple and ch == '"':
            raw = src[i + 1:j]
            j += 1
            cur_col += 1
            break
        j += 1
        cur_col += 1
    tok = Tok("STR", raw, start_line, start_col, tag=tag, length=max(1, j - i))
    tok.raw_line, tok.raw_col = content_line, content_col
    return tok, j, cur_line, cur_col


ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "{": "{", "}": "}", "0": "\0"}


def split_interpolation(tok, file):
    """원문 문자열을 [(\"lit\", text) | (\"expr\", src, line, col)] 로 분해."""
    raw = tok.value
    parts, buf = [], []
    i, n = 0, len(raw)
    line, col = tok.raw_line, tok.raw_col
    while i < n:
        c = raw[i]
        if c == "\\" and i + 1 < n:
            e = raw[i + 1]
            if e == "u" and i + 5 < n + 1:
                hexs = raw[i + 2:i + 6]
                try:
                    buf.append(chr(int(hexs, 16)))
                except ValueError:
                    raise SoriError("E001", "잘못된 \\u 이스케이프", file, line, col)
                i += 6
                col += 6
                continue
            if e not in ESCAPES:
                raise SoriError("E001", f"알 수 없는 이스케이프 '\\{e}'", file, line, col)
            buf.append(ESCAPES[e])
            i += 2
            col += 2
            continue
        if c == "{" and i + 1 < n and raw[i + 1] == "{":
            buf.append("{")
            i += 2
            col += 2
            continue
        if c == "}" and i + 1 < n and raw[i + 1] == "}":
            buf.append("}")
            i += 2
            col += 2
            continue
        if c == "{":
            if buf:
                parts.append(("lit", "".join(buf)))
                buf = []
            j, d = i + 1, 1
            while j < n and d:
                if raw[j] == "{":
                    d += 1
                elif raw[j] == "}":
                    d -= 1
                elif raw[j] == '"':
                    raise SoriError("E001", "보간 { } 안에는 문자열 리터럴을 넣을 수 없어요", file, line, col,
                                   "값을 먼저 let 변수로 만든 뒤 {변수} 로 넣으세요")
                j += 1
            if d:
                raise SoriError("E001", "보간 '{' 이 닫히지 않았어요", file, line, col)
            expr_src = raw[i + 1:j - 1]
            if not expr_src.strip():
                raise SoriError("E001", "빈 보간 {}", file, line, col, "문자 그대로의 중괄호는 {{ }} 로 쓰세요")
            parts.append(("expr", expr_src, line, col + 1))
            consumed = raw[i:j]
            line += consumed.count("\n")
            col = (len(consumed) - consumed.rfind("\n")) if "\n" in consumed else col + len(consumed)
            i = j
            continue
        if c == "}":
            raise SoriError("E001", "짝 없는 '}'", file, line, col, "문자 그대로는 }} 로 쓰세요")
        buf.append(c)
        if c == "\n":
            line += 1
            col = 1
        else:
            col += 1
        i += 1
    if buf or not parts:
        parts.append(("lit", "".join(buf)))
    return parts
