//! sori-rt — SORI Typed IR v2 Rust 해석기 (Phase B2 수직 슬라이스, 실험용)
//!
//! 사용: sori-rt <typed-ir.json> <METHOD> <PATH> [--json <본문>] [--content-type <CT>] [--auth] [--token <T>]
//!       sori-rt <typed-ir.json> --check     (라우트별 지원 여부 보고)
//! 출력: {"status": N, "body": ...}
//!
//! 주의: 서명되지 않은 IR 파일을 신뢰된 코드로 취급하지 않는다 — 구조·버전 검사 후 슬라이스가 아는 op 만 실행하고,
//! 모르는 기능이 있는 라우트는 501 로 거부한다. 운영용 서버가 아니다 (HTTP 리스너 없음).

mod interp;
mod json;

use interp::{ct_eq, Fail, Flow, Limits, Program};
use json::Value;
use std::collections::HashMap;
use std::process::exit;

fn out(status: i64, body: Value) -> ! {
    let resp = Value::Map(vec![("status".into(), Value::Int(status)), ("body".into(), body)]);
    println!("{}", json::to_string(&resp));
    exit(0)
}

fn err(status: i64, msg: &str) -> ! {
    out(status, Value::Map(vec![("error".into(), Value::Str(msg.to_string()))]))
}

fn pct_decode(s: &str) -> Result<String, String> {
    let lower = s.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") || lower.contains("%2e%2e") {
        return Err("인코딩된 경로 구분자는 허용되지 않아요".into());
    }
    let b = s.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = std::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| "잘못된 % 인코딩")?;
            v.push(u8::from_str_radix(h, 16).map_err(|_| "잘못된 % 인코딩")?);
            i += 3;
        } else if b[i] == b'+' {
            v.push(b' ');
            i += 1;
        } else {
            v.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(v).map_err(|_| "UTF-8 이 아니에요".into())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("사용: sori-rt <typed-ir.json> <METHOD> <PATH> [--json BODY] [--auth] | --check");
        exit(2);
    }
    let text = std::fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("IR 파일을 읽을 수 없어요: {}", e);
        exit(2)
    });
    let ir = json::parse(&text, 512).unwrap_or_else(|e| {
        eprintln!("IR JSON 오류: {}", e);
        exit(2)
    });
    let token = std::env::var("SORI_API_TOKEN").ok();
    let prog = Program::load(&ir, token.clone()).unwrap_or_else(|e| {
        eprintln!("IR 로드 거부: {}", e);
        exit(3)
    });
    let routes = ir.list_of("routes");
    if args[2] == "--check" {
        for (i, r) in routes.iter().enumerate() {
            let tag = match prog.unsupported.get(&i) {
                Some(why) => format!("unsupported ({})", why),
                None => "supported".into(),
            };
            println!("{} {} {}", r.str_of("method").unwrap_or(""), r.str_of("path").unwrap_or(""), tag);
        }
        exit(0);
    }
    let uses_bearer = routes.iter().any(|r| r.get("access").and_then(|a| a.str_of("kind")) == Some("bearer"));
    if uses_bearer {
        match &token {
            Some(t) if t.len() >= 32 && t.len() <= 4096 && !t.contains('\n') && !t.contains('\r') => {}
            _ => {
                eprintln!("기동 거부: guard bearer 라우트가 있는데 SORI_API_TOKEN 이 없거나 32자 미만이에요");
                exit(3)
            }
        }
    }
    let method = args[2].to_uppercase();
    let target = args[3].clone();
    let mut body: Option<String> = None;
    let mut ctype = "application/json".to_string();
    let mut auth: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                body = args.get(i + 1).cloned();
                i += 2
            }
            "--content-type" => {
                ctype = args.get(i + 1).cloned().unwrap_or_default();
                i += 2
            }
            "--auth" => {
                auth = token.clone();
                i += 1
            }
            "--token" => {
                auth = args.get(i + 1).cloned();
                i += 2
            }
            _ => {
                eprintln!("알 수 없는 인자 {}", args[i]);
                exit(2)
            }
        }
    }
    // 라우팅 (정규식 없음, 세그먼트 정확 매칭)
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    if path.contains('\\') || path.contains('\0') {
        err(400, "잘못된 경로 문자");
    }
    let segs: Vec<String> = match path.trim_matches('/').split('/').filter(|s| !s.is_empty()).map(pct_decode).collect() {
        Ok(v) => v,
        Err(e) => err(400, &e),
    };
    if segs.iter().any(|s| s == ".." || s == ".") {
        err(400, "경로에 '..' 를 쓸 수 없어요");
    }
    let mut allowed = Vec::new();
    let mut found: Option<(usize, HashMap<String, String>)> = None;
    for (idx, r) in routes.iter().enumerate() {
        let rpath = r.str_of("path").unwrap_or("/");
        let rsegs: Vec<&str> = rpath.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        if rsegs.len() != segs.len() {
            continue;
        }
        let mut params = HashMap::new();
        let mut ok = true;
        for (rs, s) in rsegs.iter().zip(segs.iter()) {
            if rs.starts_with('{') && rs.ends_with('}') {
                params.insert(rs[1..rs.len() - 1].to_string(), s.clone());
            } else if rs != s {
                ok = false;
                break;
            }
        }
        if ok {
            if r.str_of("method") == Some(method.as_str()) {
                found = Some((idx, params));
                break;
            }
            allowed.push(r.str_of("method").unwrap_or("").to_string());
        }
    }
    let (idx, pparams) = match found {
        Some(f) => f,
        None if !allowed.is_empty() => err(405, "허용되지 않는 메서드"),
        None => err(404, "not found"),
    };
    let route = &routes[idx];
    if let Some(why) = prog.unsupported.get(&idx) {
        out(501, Value::Map(vec![
            ("error".into(), Value::Str("Rust 백엔드 슬라이스가 지원하지 않는 라우트예요".into())),
            ("reason".into(), Value::Str(why.clone())),
        ]));
    }
    // 접근 정책 — 입력 파싱보다 먼저
    match route.get("access").and_then(|a| a.str_of("kind")) {
        Some("public") => {}
        Some("bearer") => {
            let expected = prog.token.clone().unwrap_or_default();
            match &auth {
                Some(t) if !expected.is_empty() && ct_eq(t.as_bytes(), expected.as_bytes()) => {}
                _ => err(401, "unauthorized"),
            }
        }
        _ => err(403, "forbidden"),
    }
    // 쿼리 파싱 (중복 거부)
    let mut qs: HashMap<String, String> = HashMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (k, v) = match (pct_decode(k), pct_decode(v)) {
            (Ok(k), Ok(v)) => (k, v),
            _ => err(400, "잘못된 쿼리 인코딩"),
        };
        if qs.insert(k.clone(), v).is_some() {
            err(400, &format!("쿼리 파라미터 '{}' 이(가) 여러 번 왔어요 (파라미터 오염 차단)", k));
        }
    }
    let mut env: HashMap<String, Value> = HashMap::new();
    let body_types: Vec<String> = Vec::new();
    let _ = body_types;
    for p in route.list_of("params") {
        let name = p.str_of("name").unwrap_or("");
        let t = p.get("type").unwrap_or(&Value::Null);
        let res = match p.str_of("source") {
            Some("path") => prog.coerce(t, &Value::Str(pparams.get(name).cloned().unwrap_or_default()), name, true),
            Some("query") => match qs.get(name) {
                Some(v) => prog.coerce(t, &Value::Str(v.clone()), name, true),
                None => match p.get("default") {
                    Some(d) if *d != Value::Null => Ok(d.get("v").cloned().unwrap_or(Value::Null)),
                    _ if t.str_of("k") == Some("Opt") => Ok(Value::Null),
                    _ => Err(Fail::Input(format!("쿼리 파라미터 '{}' 이(가) 필요해요", name))),
                },
            },
            Some("body") => {
                let raw = match &body {
                    Some(b) if !b.is_empty() => b,
                    _ => err(400, "요청 본문(body)이 필요해요"),
                };
                if ctype.split(';').next().unwrap_or("").trim().to_ascii_lowercase() != "application/json" {
                    err(415, "본문 형식은 application/json 만 받아요 (Rust 슬라이스)");
                }
                match json::parse(raw, 32) {
                    Ok(v) => prog.coerce(t, &v, "body", false),
                    Err(e) => Err(Fail::Input(e)),
                }
            }
            _ => Err(Fail::Runtime("지원하지 않는 파라미터".into())),
        };
        match res {
            Ok(v) => {
                env.insert(name.to_string(), v);
            }
            Err(Fail::Input(m)) => err(400, &m),
            Err(_) => err(500, "internal error"),
        }
    }
    let mut steps = 0u64;
    let lim = Limits { max_steps: 2_000_000 };
    match prog.exec_block(route.list_of("body"), &mut env, &mut steps, &lim) {
        Ok(Flow::Return(v)) => out(200, v),
        Ok(_) => out(204, Value::Null),
        Err(Fail::Input(m)) => err(400, &m),
        Err(Fail::Runtime(m)) | Err(Fail::Limit(m)) => {
            eprintln!("runtime error: {}", m);
            err(500, "internal error")
        }
    }
}
