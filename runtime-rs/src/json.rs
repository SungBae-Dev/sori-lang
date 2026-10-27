//! 엄격 JSON (std 전용): 중복 키 거부, NaN/Infinity 거부, 깊이 제한, 순서 보존 객체.

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn str_of(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn list_of(&self, key: &str) -> &[Value] {
        match self.get(key) {
            Some(Value::List(v)) => v.as_slice(),
            _ => &[],
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "none",
            Value::Bool(_) => "Bool",
            Value::Int(_) => "Int",
            Value::Float(_) => "Float",
            Value::Str(_) => "Str",
            Value::List(_) => "List",
            Value::Map(_) => "Map",
        }
    }
}

pub struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    max_depth: usize,
}

pub fn parse(text: &str, max_depth: usize) -> Result<Value, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0, max_depth };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err("JSON 뒤에 남는 문자가 있어요".into());
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("잘못된 JSON 토큰 (위치 {})", self.i))
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > self.max_depth {
            return Err(format!("JSON 중첩이 너무 깊어요 (최대 {})", self.max_depth));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("잘못된 JSON (위치 {}) — NaN/Infinity 는 허용되지 않아요", self.i)),
        }
    }
    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.i += 1;
        let mut out: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Map(out));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err("객체 키는 문자열이어야 해요".into());
            }
            let k = self.string()?;
            if out.iter().any(|(e, _)| *e == k) {
                return Err(format!("JSON 에 중복 키 '{}' 가 있어요 (해석 충돌 공격 방지)", k));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err("':' 가 필요해요".into());
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            out.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Map(out));
                }
                _ => return Err("',' 또는 '}' 가 필요해요".into()),
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::List(out));
        }
        loop {
            self.ws();
            out.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::List(out));
                }
                _ => return Err("',' 또는 ']' 가 필요해요".into()),
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.s.len() {
            return Err("잘못된 \\u 이스케이프".into());
        }
        let h = std::str::from_utf8(&self.s[self.i..self.i + 4]).map_err(|_| "잘못된 \\u".to_string())?;
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| "잘못된 \\u".into())
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.s.len() && self.s[self.i] != b'"' && self.s[self.i] != b'\\' {
                if self.s[self.i] < 0x20 {
                    return Err("문자열에 제어 문자가 있어요".into());
                }
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|_| "UTF-8 이 아니에요".to_string())?);
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = self.peek().ok_or("잘못된 이스케이프")?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                if self.s[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo.wrapping_sub(0xDC00) & 0x3FF);
                                } else {
                                    return Err("짝 없는 서로게이트".into());
                                }
                            }
                            out.push(char::from_u32(cp).ok_or("잘못된 코드 포인트")?);
                        }
                        _ => return Err("알 수 없는 이스케이프".into()),
                    }
                }
                _ => return Err("문자열이 닫히지 않았어요".into()),
            }
        }
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.i += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            float = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let t = std::str::from_utf8(&self.s[start..self.i]).unwrap();
        if !float {
            if let Ok(n) = t.parse::<i64>() {
                return Ok(Value::Int(n));
            }
        }
        let f: f64 = t.parse().map_err(|_| format!("잘못된 숫자 {}", t))?;
        if !f.is_finite() {
            return Err("JSON 숫자가 너무 커요".into());
        }
        Ok(Value::Float(f))
    }
}

pub fn fmt_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{:.1}", f)
    } else {
        format!("{}", f)
    }
}

pub fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn dump(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Float(f) => out.push_str(&fmt_float(*f)),
        Value::Str(s) => escape(s, out),
        Value::List(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                dump(x, out);
            }
            out.push(']');
        }
        Value::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape(k, out);
                out.push(':');
                dump(x, out);
            }
            out.push('}');
        }
    }
}

pub fn to_string(v: &Value) -> String {
    let mut s = String::new();
    dump(v, &mut s);
    s
}
