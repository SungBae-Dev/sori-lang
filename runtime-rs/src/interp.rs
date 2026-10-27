//! SORI Typed IR v2 해석기 — Rust Backend 수직 슬라이스.
//!
//! 지원 범위(슬라이스): 레코드/범위 입력 검증(엄격 JSON), public/bearer/deny 접근 정책, 라우팅(404/405),
//! let/var/대입/if/while/for/return/break/continue, 산술·비교·논리·조건식, 문자열 보간(cat),
//! 맵/목록 리터럴, 필드·인덱스 접근, 내장 len/str/abs/min/max/int/float.
//! 그 밖의 IR(std 모듈, 사용자 함수, guard, sql/html, 람다 …)을 쓰는 라우트는 '미지원'으로 표시하고
//! 요청 시 501 을 돌려준다 — 조용히 다르게 실행하지 않는다.

use crate::json::{fmt_float, Value};
use std::collections::HashMap;

pub struct Limits {
    pub max_steps: u64,
}

pub enum Flow {
    Normal,
    Return(Value),
    Break,
    Continue,
}

#[derive(Debug)]
pub enum Fail {
    Input(String),
    Runtime(String),
    Limit(String),
}

#[allow(dead_code)]
pub struct Program<'a> {
    pub ir: &'a Value,
    pub records: HashMap<String, &'a Value>,
    pub globals: HashMap<String, Value>,
    pub unsupported: HashMap<usize, String>,
    pub token: Option<String>,
}

const EXPR_OK: &[&str] = &[
    "lit", "var", "list", "map", "field", "index", "binop", "unop", "not", "logic", "compare", "cond", "cat", "call", "slice",
];
const STMT_OK: &[&str] = &["let", "assign", "if", "while", "for", "return", "break", "continue", "pass", "expr"];
const BUILTINS_OK: &[&str] = &["len", "str", "abs", "min", "max", "int", "float"];

fn op(n: &Value) -> &str {
    n.str_of("op").unwrap_or("?")
}

/// IR 노드 트리에서 슬라이스가 지원하지 않는 첫 요소를 찾는다.
fn unsupported_in(n: &Value) -> Option<String> {
    match n {
        Value::Map(m) => {
            if let Some(Value::Str(o)) = n.get("op") {
                let is_stmt = n.get("t").is_none();
                let ok = if is_stmt { STMT_OK.contains(&o.as_str()) } else { EXPR_OK.contains(&o.as_str()) };
                if !ok {
                    return Some(format!("op '{}'", o));
                }
                if o == "call" {
                    let f = n.get("fn").unwrap_or(&Value::Null);
                    let is_builtin = op(f) == "var" && f.str_of("scope") == Some("builtin")
                        && BUILTINS_OK.contains(&f.str_of("name").unwrap_or(""));
                    if !is_builtin {
                        return Some("builtin 이 아닌 함수 호출".into());
                    }
                }
                if o == "var" && n.str_of("scope") == Some("builtin") && !BUILTINS_OK.contains(&n.str_of("name").unwrap_or("")) {
                    return Some(format!("builtin '{}'", n.str_of("name").unwrap_or("")));
                }
            }
            for (k, v) in m {
                if k == "type" || k == "at" {
                    continue;
                }
                if let Some(r) = unsupported_in(v) {
                    return Some(r);
                }
            }
            None
        }
        Value::List(xs) => xs.iter().find_map(unsupported_in),
        _ => None,
    }
}

fn type_unsupported(t: &Value, records: &HashMap<String, &Value>, depth: usize) -> Option<String> {
    if depth > 8 {
        return Some("타입 중첩이 너무 깊어요".into());
    }
    match t.str_of("k") {
        Some("Int") | Some("Float") | Some("Str") | Some("Bool") | Some("Json") | Some("Any") => None,
        Some("List") | Some("Map") | Some("Opt") => type_unsupported(t.get("of").unwrap_or(&Value::Null), records, depth + 1),
        Some("Ref") => {
            let name = t.str_of("name").unwrap_or("");
            let rec = records.get(name)?;
            for f in rec.list_of("fields") {
                if let Some(r) = type_unsupported(f.get("type").unwrap_or(&Value::Null), records, depth + 1) {
                    return Some(r);
                }
                if let Some(d) = f.get("default") {
                    if *d != Value::Null && op(d) != "lit" {
                        return Some("리터럴이 아닌 필드 기본값".into());
                    }
                }
            }
            None
        }
        Some(k) => Some(format!("타입 {}", k)),
        None => Some("타입 없음".into()),
    }
}

impl<'a> Program<'a> {
    pub fn load(ir: &'a Value, token: Option<String>) -> Result<Program<'a>, String> {
        if ir.str_of("ir_version") != Some("sori/ir/v2") {
            return Err("sori/ir/v2 IR 이 아니에요".into());
        }
        let mut records = HashMap::new();
        for t in ir.list_of("types") {
            records.insert(t.str_of("name").unwrap_or("").to_string(), t);
        }
        let mut unsupported = HashMap::new();
        let global_issue = if !ir.list_of("uses").is_empty() {
            Some("use (std/py 모듈)".to_string())
        } else {
            ir.list_of("init").iter().find_map(unsupported_in)
        };
        for (i, r) in ir.list_of("routes").iter().enumerate() {
            let mut issue = global_issue.clone().or_else(|| r.list_of("body").iter().find_map(unsupported_in));
            let kind = r.get("access").and_then(|a| a.str_of("kind")).unwrap_or("deny");
            if kind == "guard" {
                issue = Some("사용자 정의 guard".into());
            }
            for p in r.list_of("params") {
                match p.str_of("source") {
                    Some("req") => issue = Some("req 파라미터".into()),
                    Some(_) => {
                        if let Some(t) = p.get("type") {
                            if let Some(x) = type_unsupported(t, &records, 0) {
                                issue = Some(x);
                            }
                        }
                        if let Some(d) = p.get("default") {
                            if *d != Value::Null && op(d) != "lit" {
                                issue = Some("리터럴이 아닌 파라미터 기본값".into());
                            }
                        }
                    }
                    None => {}
                }
            }
            if let Some(x) = issue {
                unsupported.insert(i, x);
            }
        }
        let mut prog = Program { ir, records, globals: HashMap::new(), unsupported, token };
        if global_issue.is_none() {
            let mut env = HashMap::new();
            let mut steps = 0u64;
            for st in ir.list_of("init") {
                prog.exec(st, &mut env, &mut steps, &Limits { max_steps: 100_000 }).map_err(|e| format!("초기화 실패: {:?}", e))?;
            }
            for (k, v) in env {
                if let Some(name) = k.strip_prefix("@global:") {
                    prog.globals.insert(name.to_string(), v);
                }
            }
        }
        Ok(prog)
    }

    // ------------------------------------------------------------ 입력 검증 (엄격)
    pub fn coerce(&self, t: &Value, v: &Value, label: &str, from_text: bool) -> Result<Value, Fail> {
        let bad = |msg: String| Err(Fail::Input(msg));
        let k = t.str_of("k").unwrap_or("Any");
        let lo = t.get("lo");
        let hi = t.get("hi");
        let num = |x: &Value| -> Option<f64> {
            match x {
                Value::Int(n) => Some(*n as f64),
                Value::Float(f) => Some(*f),
                _ => None,
            }
        };
        let in_range = |m: f64| -> bool {
            match (lo.and_then(num), hi.and_then(num)) {
                (Some(a), Some(b)) => a <= m && m <= b,
                _ => true,
            }
        };
        match k {
            "Opt" => {
                if *v == Value::Null || (from_text && *v == Value::Str(String::new())) {
                    Ok(Value::Null)
                } else {
                    self.coerce(t.get("of").unwrap(), v, label, from_text)
                }
            }
            "Int" => {
                let n = match v {
                    Value::Int(n) => *n,
                    Value::Str(s) if from_text => s.trim().parse::<i64>().map_err(|_| Fail::Input(format!("'{}' 은(는) 정수(Int)여야 해요", label)))?,
                    _ => return bad(format!("'{}' 은(는) 정수(Int)여야 해요", label)),
                };
                if !in_range(n as f64) {
                    return bad(format!("'{}' 값이 범위를 벗어났어요", label));
                }
                Ok(Value::Int(n))
            }
            "Float" => {
                let f = match v {
                    Value::Int(n) => *n as f64,
                    Value::Float(f) => *f,
                    Value::Str(s) if from_text => s.trim().parse::<f64>().map_err(|_| Fail::Input(format!("'{}' 은(는) 숫자(Float)여야 해요", label)))?,
                    _ => return bad(format!("'{}' 은(는) 숫자(Float)여야 해요", label)),
                };
                if !f.is_finite() || !in_range(f) {
                    return bad(format!("'{}' 값이 범위를 벗어났어요", label));
                }
                Ok(Value::Float(f))
            }
            "Str" => match v {
                Value::Str(s) => {
                    let n = s.chars().count();
                    if n > 1_000_000 || !in_range(n as f64) {
                        return bad(format!("'{}' 길이가 범위를 벗어났어요", label));
                    }
                    Ok(v.clone())
                }
                _ => bad(format!("'{}' 은(는) 문자열(Str)이어야 해요", label)),
            },
            "Bool" => match v {
                Value::Bool(_) => Ok(v.clone()),
                Value::Str(s) if from_text => match s.to_ascii_lowercase().as_str() {
                    "true" | "1" | "on" => Ok(Value::Bool(true)),
                    "false" | "0" | "off" => Ok(Value::Bool(false)),
                    _ => bad(format!("'{}' 은(는) true/false 여야 해요", label)),
                },
                _ => bad(format!("'{}' 은(는) true/false 여야 해요", label)),
            },
            "List" => match v {
                Value::List(xs) => {
                    if xs.len() > 10_000 || !in_range(xs.len() as f64) {
                        return bad(format!("'{}' 개수가 범위를 벗어났어요", label));
                    }
                    let item = t.get("of").unwrap();
                    let mut out = Vec::with_capacity(xs.len());
                    for (i, x) in xs.iter().enumerate() {
                        out.push(self.coerce(item, x, &format!("{}[{}]", label, i), from_text)?);
                    }
                    Ok(Value::List(out))
                }
                _ => bad(format!("'{}' 은(는) 목록이어야 해요", label)),
            },
            "Map" => match v {
                Value::Map(m) => {
                    let item = t.get("of").unwrap();
                    let mut out = Vec::new();
                    for (key, x) in m {
                        out.push((key.clone(), self.coerce(item, x, &format!("{}.{}", label, key), from_text)?));
                    }
                    Ok(Value::Map(out))
                }
                _ => bad(format!("'{}' 은(는) 맵이어야 해요", label)),
            },
            "Ref" => {
                let name = t.str_of("name").unwrap_or("");
                let rec = self.records.get(name).ok_or_else(|| Fail::Runtime(format!("타입 {} 없음", name)))?;
                let data = match v {
                    Value::Map(m) => m,
                    _ => return bad(format!("'{}' 은(는) {} 객체여야 해요", label, name)),
                };
                let fields = rec.list_of("fields");
                for (key, _) in data {
                    if !fields.iter().any(|f| f.str_of("name") == Some(key.as_str())) {
                        return bad(format!("{} 에 없는 필드는 받을 수 없어요: {}", name, key));
                    }
                }
                let mut out = Vec::new();
                for f in fields {
                    let fname = f.str_of("name").unwrap_or("");
                    let ft = f.get("type").unwrap();
                    match data.iter().find(|(key, _)| key == fname) {
                        Some((_, x)) => out.push((fname.to_string(), self.coerce(ft, x, &format!("{}.{}", label, fname), from_text)?)),
                        None => match f.get("default") {
                            Some(d) if *d != Value::Null => out.push((fname.to_string(), d.get("v").cloned().unwrap_or(Value::Null))),
                            _ if ft.str_of("k") == Some("Opt") => out.push((fname.to_string(), Value::Null)),
                            _ => return bad(format!("'{}.{}' 이(가) 필요해요", label, fname)),
                        },
                    }
                }
                Ok(Value::Map(out))
            }
            _ => Ok(v.clone()),
        }
    }

    // ------------------------------------------------------------ 실행
    fn tick(&self, steps: &mut u64, lim: &Limits) -> Result<(), Fail> {
        *steps += 1;
        if *steps > lim.max_steps {
            return Err(Fail::Limit(format!("실행 단계 상한({})을 넘었어요", lim.max_steps)));
        }
        Ok(())
    }

    pub fn exec_block(&self, body: &[Value], env: &mut HashMap<String, Value>, steps: &mut u64, lim: &Limits) -> Result<Flow, Fail> {
        for st in body {
            match self.exec(st, env, steps, lim)? {
                Flow::Normal => {}
                other => return Ok(other),
            }
        }
        Ok(Flow::Normal)
    }

    fn set_var(&self, name: &str, scope: &str, v: Value, env: &mut HashMap<String, Value>) {
        if scope == "global" {
            // 슬라이스: 요청 처리 중 전역 변경은 요청 지역 사본에만 반영 (공유 상태 없음)
            env.insert(format!("@global:{}", name), v);
        } else {
            env.insert(name.to_string(), v);
        }
    }

    pub fn exec(&self, st: &Value, env: &mut HashMap<String, Value>, steps: &mut u64, lim: &Limits) -> Result<Flow, Fail> {
        self.tick(steps, lim)?;
        match op(st) {
            "let" => {
                let v = self.eval(st.get("value").unwrap(), env, steps, lim)?;
                let scope = st.str_of("scope").unwrap_or("local");
                let name = st.str_of("name").unwrap_or("");
                if scope == "global" && env.is_empty() {
                    // 초기화 단계는 Program::load 에서 globals 로 옮긴다
                }
                self.set_var(name, scope, v, env);
                Ok(Flow::Normal)
            }
            "assign" => {
                let t = st.get("target").unwrap();
                let v = self.eval(st.get("value").unwrap(), env, steps, lim)?;
                if op(t) != "var" {
                    return Err(Fail::Runtime("슬라이스는 변수 대입만 지원해요".into()));
                }
                let name = t.str_of("name").unwrap_or("");
                let scope = t.str_of("scope").unwrap_or("local");
                let o = st.str_of("o").unwrap_or("=");
                let v = if o == "=" {
                    v
                } else {
                    let cur = self.lookup(name, scope, env)?;
                    self.binop(&o[..1], &cur, &v)?
                };
                self.set_var(name, scope, v, env);
                Ok(Flow::Normal)
            }
            "expr" => {
                self.eval(st.get("x").unwrap(), env, steps, lim)?;
                Ok(Flow::Normal)
            }
            "if" => {
                for br in st.list_of("branches") {
                    if let Value::List(pair) = br {
                        if truthy(&self.eval(&pair[0], env, steps, lim)?) {
                            if let Value::List(body) = &pair[1] {
                                return self.exec_block(body, env, steps, lim);
                            }
                        }
                    }
                }
                if let Some(Value::List(body)) = st.get("else") {
                    return self.exec_block(body, env, steps, lim);
                }
                Ok(Flow::Normal)
            }
            "while" => {
                while truthy(&self.eval(st.get("c").unwrap(), env, steps, lim)?) {
                    self.tick(steps, lim)?;
                    match self.exec_block(st.list_of("body"), env, steps, lim)? {
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(Flow::Return(v)),
                        _ => {}
                    }
                }
                Ok(Flow::Normal)
            }
            "for" => {
                let it = self.eval(st.get("iter").unwrap(), env, steps, lim)?;
                let items: Vec<Value> = match it {
                    Value::List(xs) => xs,
                    Value::Map(m) => m.into_iter().map(|(k, _)| Value::Str(k)).collect(),
                    Value::Str(s) => s.chars().map(|c| Value::Str(c.to_string())).collect(),
                    other => return Err(Fail::Runtime(format!("{} 은(는) 반복할 수 없어요", other.type_name()))),
                };
                let names = st.list_of("names");
                let scope = st.str_of("scope").unwrap_or("local");
                for item in items {
                    self.tick(steps, lim)?;
                    if names.len() == 1 {
                        if let Value::Str(n) = &names[0] {
                            self.set_var(n, scope, item, env);
                        }
                    } else {
                        return Err(Fail::Runtime("슬라이스는 for a, b 를 지원하지 않아요".into()));
                    }
                    match self.exec_block(st.list_of("body"), env, steps, lim)? {
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(Flow::Return(v)),
                        _ => {}
                    }
                }
                Ok(Flow::Normal)
            }
            "return" => {
                let v = match st.get("x") {
                    Some(x) if *x != Value::Null => self.eval(x, env, steps, lim)?,
                    _ => Value::Null,
                };
                Ok(Flow::Return(v))
            }
            "break" => Ok(Flow::Break),
            "continue" => Ok(Flow::Continue),
            "pass" => Ok(Flow::Normal),
            other => Err(Fail::Runtime(format!("지원하지 않는 문장 {}", other))),
        }
    }

    fn lookup(&self, name: &str, scope: &str, env: &HashMap<String, Value>) -> Result<Value, Fail> {
        if scope != "global" {
            if let Some(v) = env.get(name) {
                return Ok(v.clone());
            }
        }
        if let Some(v) = env.get(&format!("@global:{}", name)) {
            return Ok(v.clone());
        }
        self.globals.get(name).cloned().ok_or_else(|| Fail::Runtime(format!("'{}' 이(가) 정의되지 않았어요", name)))
    }

    pub fn eval(&self, n: &Value, env: &mut HashMap<String, Value>, steps: &mut u64, lim: &Limits) -> Result<Value, Fail> {
        match op(n) {
            "lit" => Ok(n.get("v").cloned().unwrap_or(Value::Null)),
            "var" => self.lookup(n.str_of("name").unwrap_or(""), n.str_of("scope").unwrap_or("local"), env),
            "list" => {
                let mut out = Vec::new();
                for x in n.list_of("items") {
                    out.push(self.eval(x, env, steps, lim)?);
                }
                Ok(Value::List(out))
            }
            "map" => {
                let mut out: Vec<(String, Value)> = Vec::new();
                for pair in n.list_of("pairs") {
                    if let Value::List(kv) = pair {
                        let k = match self.eval(&kv[0], env, steps, lim)? {
                            Value::Str(s) => s,
                            _ => return Err(Fail::Runtime("맵 키는 Str 이어야 해요".into())),
                        };
                        let v = self.eval(&kv[1], env, steps, lim)?;
                        if let Some(slot) = out.iter_mut().find(|(e, _)| *e == k) {
                            slot.1 = v;
                        } else {
                            out.push((k, v));
                        }
                    }
                }
                Ok(Value::Map(out))
            }
            "field" => {
                let obj = self.eval(n.get("obj").unwrap(), env, steps, lim)?;
                let name = n.str_of("name").unwrap_or("");
                obj.get(name).cloned().ok_or_else(|| Fail::Runtime(format!("{} 에는 '{}' 이(가) 없어요", obj.type_name(), name)))
            }
            "index" => {
                let obj = self.eval(n.get("obj").unwrap(), env, steps, lim)?;
                let idx = self.eval(n.get("index").unwrap(), env, steps, lim)?;
                match (&obj, &idx) {
                    (Value::List(xs), Value::Int(i)) => {
                        let len = xs.len() as i64;
                        let j = if *i < 0 { len + i } else { *i };
                        if j < 0 || j >= len {
                            return Err(Fail::Runtime("목록 범위를 벗어났어요".into()));
                        }
                        Ok(xs[j as usize].clone())
                    }
                    (Value::Map(_), Value::Str(k)) => obj.get(k).cloned().ok_or_else(|| Fail::Runtime(format!("맵에 '{}' 키가 없어요", k))),
                    _ => Err(Fail::Runtime(format!("{} 은(는) 그 방법으로 인덱스할 수 없어요", obj.type_name()))),
                }
            }
            "slice" => {
                let obj = self.eval(n.get("obj").unwrap(), env, steps, lim)?;
                let lo = match n.get("lo") {
                    Some(x) if *x != Value::Null => Some(self.eval(x, env, steps, lim)?),
                    _ => None,
                };
                let hi = match n.get("hi") {
                    Some(x) if *x != Value::Null => Some(self.eval(x, env, steps, lim)?),
                    _ => None,
                };
                if let Value::List(xs) = obj {
                    let len = xs.len() as i64;
                    let norm = |v: Option<Value>, d: i64| -> i64 {
                        match v {
                            Some(Value::Int(i)) => (if i < 0 { len + i } else { i }).clamp(0, len),
                            _ => d,
                        }
                    };
                    let (a, b) = (norm(lo, 0), norm(hi, len));
                    Ok(Value::List(if a < b { xs[a as usize..b as usize].to_vec() } else { vec![] }))
                } else {
                    Err(Fail::Runtime("슬라이스는 목록만 지원해요 (슬라이스 백엔드)".into()))
                }
            }
            "binop" => {
                let a = self.eval(n.get("l").unwrap(), env, steps, lim)?;
                let b = self.eval(n.get("r").unwrap(), env, steps, lim)?;
                self.binop(n.str_of("o").unwrap_or(""), &a, &b)
            }
            "unop" => {
                let x = self.eval(n.get("x").unwrap(), env, steps, lim)?;
                match (n.str_of("o"), x) {
                    (Some("-"), Value::Int(i)) => i.checked_neg().map(Value::Int).ok_or_else(|| Fail::Runtime("정수 오버플로".into())),
                    (Some("-"), Value::Float(f)) => Ok(Value::Float(-f)),
                    (Some("+"), v @ (Value::Int(_) | Value::Float(_))) => Ok(v),
                    _ => Err(Fail::Runtime("단항 연산은 숫자에만 쓸 수 있어요".into())),
                }
            }
            "not" => Ok(Value::Bool(!truthy(&self.eval(n.get("x").unwrap(), env, steps, lim)?))),
            "logic" => {
                let l = self.eval(n.get("l").unwrap(), env, steps, lim)?;
                let and = n.str_of("o") == Some("and");
                if and != truthy(&l) {
                    Ok(l)
                } else {
                    self.eval(n.get("r").unwrap(), env, steps, lim)
                }
            }
            "compare" => {
                let mut left = self.eval(n.get("l").unwrap(), env, steps, lim)?;
                let ops = n.list_of("ops");
                let rs = n.list_of("rs");
                for (o, rn) in ops.iter().zip(rs.iter()) {
                    let right = self.eval(rn, env, steps, lim)?;
                    let o = if let Value::Str(s) = o { s.as_str() } else { "" };
                    if !compare(o, &left, &right)? {
                        return Ok(Value::Bool(false));
                    }
                    left = right;
                }
                Ok(Value::Bool(true))
            }
            "cond" => {
                if truthy(&self.eval(n.get("c").unwrap(), env, steps, lim)?) {
                    self.eval(n.get("then").unwrap(), env, steps, lim)
                } else {
                    self.eval(n.get("orelse").unwrap(), env, steps, lim)
                }
            }
            "cat" => {
                let lits = n.list_of("lits");
                let args = n.list_of("args");
                let mut out = String::new();
                for (i, l) in lits.iter().enumerate() {
                    if let Value::Str(s) = l {
                        out.push_str(s);
                    }
                    if i < args.len() {
                        out.push_str(&tostr(&self.eval(&args[i], env, steps, lim)?, false));
                    }
                }
                Ok(Value::Str(out))
            }
            "call" => {
                self.tick(steps, lim)?;
                let f = n.get("fn").unwrap();
                let name = f.str_of("name").unwrap_or("");
                let mut args = Vec::new();
                for a in n.list_of("args") {
                    args.push(self.eval(a, env, steps, lim)?);
                }
                builtin(name, &args)
            }
            other => Err(Fail::Runtime(format!("지원하지 않는 식 {}", other))),
        }
    }

    fn binop(&self, o: &str, a: &Value, b: &Value) -> Result<Value, Fail> {
        use Value::*;
        let err = || Fail::Runtime(format!("{} {} {} 연산은 할 수 없어요", a.type_name(), o, b.type_name()));
        if matches!(a, Bool(_)) || matches!(b, Bool(_)) {
            return Err(Fail::Runtime(format!("Bool 은 숫자 연산({})에 쓸 수 없어요", o)));
        }
        let of = || Fail::Runtime("정수 오버플로".into());
        match (o, a, b) {
            ("+", Str(x), Str(y)) => Ok(Str(format!("{}{}", x, y))),
            ("+", List(x), List(y)) => Ok(List(x.iter().chain(y.iter()).cloned().collect())),
            (_, Int(x), Int(y)) => match o {
                "+" => x.checked_add(*y).map(Int).ok_or_else(of),
                "-" => x.checked_sub(*y).map(Int).ok_or_else(of),
                "*" => x.checked_mul(*y).map(Int).ok_or_else(of),
                "/" => {
                    if *y == 0 {
                        Err(Fail::Runtime("0 으로 나눌 수 없어요".into()))
                    } else {
                        Ok(Float(*x as f64 / *y as f64))
                    }
                }
                "//" => {
                    if *y == 0 {
                        Err(Fail::Runtime("0 으로 나눌 수 없어요".into()))
                    } else {
                        let q = x / y;
                        Ok(Int(if (x % y != 0) && ((*x < 0) != (*y < 0)) { q - 1 } else { q }))
                    }
                }
                "%" => {
                    if *y == 0 {
                        Err(Fail::Runtime("0 으로 나눌 수 없어요".into()))
                    } else {
                        Ok(Int(((x % y) + y) % y))
                    }
                }
                _ => Err(err()),
            },
            (_, Int(_) | Float(_), Int(_) | Float(_)) => {
                let x = num(a).unwrap();
                let y = num(b).unwrap();
                match o {
                    "+" => Ok(Float(x + y)),
                    "-" => Ok(Float(x - y)),
                    "*" => Ok(Float(x * y)),
                    "/" | "//" | "%" if y == 0.0 => Err(Fail::Runtime("0 으로 나눌 수 없어요".into())),
                    "/" => Ok(Float(x / y)),
                    "//" => Ok(Float((x / y).floor())),
                    "%" => Ok(Float(x - y * (x / y).floor())),
                    _ => Err(err()),
                }
            }
            _ => Err(err()),
        }
    }
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => !s.is_empty(),
        Value::List(x) => !x.is_empty(),
        Value::Map(m) => !m.is_empty(),
    }
}

fn eq(a: &Value, b: &Value) -> bool {
    // 파이썬 의미론과 동일: 숫자끼리는 값 비교 (1 == 1.0, true == 1)
    match (num(a), num(b)) {
        (Some(x), Some(y)) if !matches!(a, Value::Str(_)) && !matches!(b, Value::Str(_)) => x == y,
        _ => match (a, b) {
            (Value::List(x), Value::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq(p, q)),
            (Value::Map(x), Value::Map(y)) => x.len() == y.len() && x.iter().all(|(k, v)| b.get(k).map_or(false, |w| eq(v, w))),
            _ => a == b,
        },
    }
}

fn compare(o: &str, a: &Value, b: &Value) -> Result<bool, Fail> {
    match o {
        "==" => Ok(eq(a, b)),
        "!=" => Ok(!eq(a, b)),
        "in" | "not in" => {
            let r = match b {
                Value::List(xs) => xs.iter().any(|x| eq(a, x)),
                Value::Map(_) => matches!(a, Value::Str(k) if b.get(k).is_some()),
                Value::Str(s) => matches!(a, Value::Str(x) if s.contains(x.as_str())),
                _ => return Err(Fail::Runtime("'in' 오른쪽은 목록/맵/문자열이어야 해요".into())),
            };
            Ok(if o == "in" { r } else { !r })
        }
        _ => {
            let ord = match (a, b) {
                (Value::Str(x), Value::Str(y)) => x.cmp(y),
                _ if !matches!(a, Value::Bool(_)) && !matches!(b, Value::Bool(_)) => {
                    match (num(a), num(b)) {
                        (Some(x), Some(y)) => x.partial_cmp(&y).ok_or_else(|| Fail::Runtime("비교할 수 없어요".into()))?,
                        _ => return Err(Fail::Runtime(format!("{} {} {} 크기 비교는 할 수 없어요", a.type_name(), o, b.type_name()))),
                    }
                }
                _ => return Err(Fail::Runtime("Bool 은 크기 비교할 수 없어요".into())),
            };
            use std::cmp::Ordering::*;
            Ok(match o {
                "<" => ord == Less,
                ">" => ord == Greater,
                "<=" => ord != Greater,
                ">=" => ord != Less,
                _ => false,
            })
        }
    }
}

pub fn tostr(v: &Value, nested: bool) -> String {
    match v {
        Value::Null => "none".into(),
        Value::Bool(b) => (if *b { "true" } else { "false" }).into(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => fmt_float(*f),
        Value::Str(s) => {
            if nested {
                let mut o = String::new();
                crate::json::escape(s, &mut o);
                o
            } else {
                s.clone()
            }
        }
        Value::List(xs) => format!("[{}]", xs.iter().map(|x| tostr(x, true)).collect::<Vec<_>>().join(", ")),
        Value::Map(m) => format!(
            "{{{}}}",
            m.iter().map(|(k, x)| format!("{}: {}", tostr(&Value::Str(k.clone()), true), tostr(x, true))).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn builtin(name: &str, args: &[Value]) -> Result<Value, Fail> {
    let a0 = args.first().unwrap_or(&Value::Null);
    match name {
        "len" => match a0 {
            Value::Str(s) => Ok(Value::Int(s.chars().count() as i64)),
            Value::List(x) => Ok(Value::Int(x.len() as i64)),
            Value::Map(m) => Ok(Value::Int(m.len() as i64)),
            _ => Err(Fail::Runtime("len() 은 목록/맵/문자열에만 쓸 수 있어요".into())),
        },
        "str" => Ok(Value::Str(tostr(a0, false))),
        "abs" => match a0 {
            Value::Int(i) => i.checked_abs().map(Value::Int).ok_or_else(|| Fail::Runtime("정수 오버플로".into())),
            Value::Float(f) => Ok(Value::Float(f.abs())),
            _ => Err(Fail::Runtime("abs() 는 숫자에만".into())),
        },
        "int" => match a0 {
            Value::Int(_) => Ok(a0.clone()),
            Value::Float(f) => Ok(Value::Int(f.trunc() as i64)),
            Value::Str(s) => s.trim().parse::<i64>().map(Value::Int).map_err(|_| Fail::Runtime("int() 변환 실패".into())),
            _ => Err(Fail::Runtime("int() 변환 실패".into())),
        },
        "float" => num(a0).map(Value::Float).ok_or_else(|| Fail::Runtime("float() 변환 실패".into())),
        "min" | "max" => {
            let xs: Vec<Value> = if args.len() == 1 {
                if let Value::List(v) = a0 { v.clone() } else { vec![] }
            } else {
                args.to_vec()
            };
            let mut best: Option<Value> = None;
            for x in xs {
                best = Some(match best {
                    None => x,
                    Some(b) => {
                        let less = compare("<", &x, &b)?;
                        if (name == "min") == less { x } else { b }
                    }
                });
            }
            best.ok_or_else(|| Fail::Runtime(format!("{}() 에 빈 목록", name)))
        }
        _ => Err(Fail::Runtime(format!("지원하지 않는 내장 함수 {}", name))),
    }
}

/// 상수 시간 비교 (bearer 토큰)
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}
