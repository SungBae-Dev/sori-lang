"""SORI diagnostics: 사람(한국어)과 AI(JSON) 모두가 읽을 수 있는 오류 형식."""
import difflib
import json

CODES = {
    # 렉서/파서
    "E001": "어휘 오류",
    "E002": "구문 오류",
    # 이름/스코프
    "E101": "선언되지 않은 이름",
    "E102": "불변(let) 값 재할당",
    "E103": "중복 선언",
    "E104": "예약어 사용",
    "E105": "'_' 로 시작하는 이름/속성 금지 (샌드박스 보호)",
    "E106": "금지된 속성 접근 (샌드박스 보호)",
    "E107": "타입 오류 (정적 검사)",
    "E108": "없는 필드/메서드",
    "E109": "안전하지 않은 SQL 사용",
    # 권한
    "E201": "선언되지 않은 권한",
    "E202": "존재하지 않는 표준 모듈",
    "E203": "sori.toml 정책 오류",
    "E203": "sori.toml 정책 오류",
    # 라우트
    "E301": "라우트 접근 정책 누락",
    "E302": "guard 참조 오류",
    "E303": "경로 파라미터 불일치",
    "E304": "중복 라우트",
    "E305": "범위 없는 입력 (strict_inputs)",
    "E306": "public 라우트의 워커 호출",
    "E305": "범위 없는 입력 (strict_inputs)",
    # 템플릿
    "E401": "위험한 HTML 문맥에서의 보간",
    # 경고
    "W301": "unsafe_html 사용",
    "W302": "Any 타입 사용 (검증 우회)",
    "W303": "인증 없는 공개 쓰기 엔드포인트",
    "W304": "범위가 선언되지 않은 입력",
    "W305": "인증 없는 AI 호출",
    "W306": "개발 전용 기능 사용 (use py)",
    "W304": "범위가 선언되지 않은 입력",
}


class SoriError(Exception):
    def __init__(self, code, message, file="<sori>", line=0, col=0, hint=None, severity="error", length=1):
        super().__init__(message)
        self.code = code
        self.message = message
        self.file = file
        self.line = line
        self.col = col
        self.hint = hint
        self.severity = severity
        self.length = max(1, length)

    def to_dict(self):
        return {
            "severity": self.severity,
            "code": "SORI-" + self.code,
            "category": CODES.get(self.code, ""),
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "hint": self.hint,
        }

    def render(self, sources=None):
        kind = "error" if self.severity == "error" else "warning"
        out = [f"{kind}[SORI-{self.code}]: {self.message}", f"  --> {self.file}:{self.line}:{self.col}"]
        src = (sources or {}).get(self.file)
        if src and self.line > 0:
            lines = src.splitlines()
            if self.line <= len(lines):
                text = lines[self.line - 1]
                num = str(self.line)
                pad = " " * len(num)
                out.append(f"{pad} |")
                out.append(f"{num} | {text}")
                out.append(f"{pad} | " + " " * max(0, self.col - 1) + "^" * self.length)
        if self.hint:
            out.append(f"   = 힌트: {self.hint}")
        return "\n".join(out)


def did_you_mean(name, candidates):
    m = difflib.get_close_matches(name, list(candidates), n=1, cutoff=0.6)
    return f"'{m[0]}' 을(를) 말한 건가요?" if m else None


def render_all(diags, sources, as_json=False):
    if as_json:
        return json.dumps([d.to_dict() for d in diags], ensure_ascii=False, indent=2)
    return "\n\n".join(d.render(sources) for d in diags)
