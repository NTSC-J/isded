use crate::s_expression::S;
use chrono::prelude::*;
use failure::{bail, Error};
//use std::prelude::v1::*;
use std::result::Result;

// TODO
fn get_trusted_time() -> Result<DateTime<Utc>, Error> {
    Ok(Utc.ymd(2020, 1, 1).and_hms(0, 0, 0))
}
fn get_monotonic_counter() -> Result<i64, Error> {
    Ok(0)
}

#[derive(Debug, PartialEq)]
pub enum ST {
    I64(i64),
    Bool(bool),
}

fn atom_content(e: &S) -> Result<&str, Error> {
    match e {
        S::Atom(s) => Ok(&s),
        _ => bail!("expected atom"),
    }
}

// strict: 文法チェックを行う
// dry_run: MEにアクセスしない
pub fn interpret(expr: &S, strict: bool, dry_run: bool) -> Result<ST, Error> {
    let interpret_ = |e| interpret(e, strict, dry_run);
    match expr {
        S::List(v) => {
            let f = atom_content(&v[0])?; // FIXME: panicする
            let test_argc = |argc| {
                if v.len() - 1 != argc {
                    bail!("{} takes exactly {} arguments", f, argc);
                } else {
                    Ok(())
                }
            };
            let test_bool = || {
                for e in v.iter().skip(1).map(interpret_) {
                    match e {
                        Ok(ST::Bool(_)) => (),
                        _ => bail!("expected boolean value"),
                    }
                }
                Ok(())
            };
            match f {
                // <: I64 -> I64 -> Bool
                "<" => {
                    test_argc(2)?;
                    match (interpret_(&v[1]), interpret_(&v[2])) {
                        (Ok(ST::I64(a)), Ok(ST::I64(b))) => Ok(ST::Bool(a < b)),
                        _ => bail!("error in function <"),
                    }
                }
                // >: I64 -> I64 -> Bool
                ">" => {
                    test_argc(2)?;
                    match (interpret_(&v[1]), interpret_(&v[2])) {
                        (Ok(ST::I64(a)), Ok(ST::I64(b))) => Ok(ST::Bool(a > b)),
                        _ => bail!("error in function >"),
                    }
                }
                // ==: a -> a -> Bool
                "==" => {
                    test_argc(2)?;
                    match (interpret_(&v[1]), interpret_(&v[2])) {
                        (Ok(ST::I64(a)), Ok(ST::I64(b))) => Ok(ST::Bool(a == b)),
                        (Ok(ST::Bool(a)), Ok(ST::Bool(b))) => Ok(ST::Bool(a == b)),
                        _ => bail!("error in function =="),
                    }
                }
                // and: Bool... -> Bool
                "and" => {
                    if strict {
                        test_bool()?;
                    }
                    for elem in v.iter().skip(1).map(interpret_) {
                        match elem {
                            Err(e) => return Err(e),
                            Ok(ST::I64(_)) => bail!("type error in function and"),
                            Ok(ST::Bool(false)) => return Ok(ST::Bool(false)),
                            Ok(ST::Bool(true)) => (),
                        }
                    }
                    Ok(ST::Bool(true))
                }
                // or: Bool... -> Bool
                "or" => {
                    if strict {
                        test_bool()?;
                    }
                    for elem in v.iter().skip(1).map(interpret_) {
                        match elem {
                            Err(e) => return Err(e),
                            Ok(ST::I64(_)) => bail!("type error in function or"),
                            Ok(ST::Bool(true)) => return Ok(ST::Bool(true)),
                            Ok(ST::Bool(false)) => (),
                        }
                    }
                    Ok(ST::Bool(false))
                }
                // not: Bool -> Bool
                "not" => {
                    test_argc(1)?;
                    test_bool()?;
                    match interpret_(&v[1]) {
                        Err(e) => Err(e),
                        Ok(ST::I64(_)) => bail!("type error in function not"),
                        Ok(ST::Bool(b)) => Ok(ST::Bool(!b)),
                    }
                }
                // rfc3339: String -> I64
                "rfc3339" => {
                    test_argc(1)?;
                    let s = atom_content(&v[1])?;
                    // オフセットが違ってもtimestampの起点は同一(Unix epoch)
                    Ok(ST::I64(
                        DateTime::<FixedOffset>::parse_from_rfc3339(&s)?.timestamp_millis(),
                    ))
                }
                // current_time: I64 （参照透過でない）
                "current_time" => {
                    if dry_run {
                        Ok(ST::I64(0))
                    } else {
                        Ok(ST::I64(get_trusted_time()?.timestamp_millis())) // 5.84億年間使える
                    }
                }
                // counter: I64 （参照透過でない）
                "counter" => {
                    if dry_run {
                        Ok(ST::I64(0))
                    } else {
                        Ok(ST::I64(get_monotonic_counter()?))
                    }
                }
                _ => bail!("unknown function"),
            }
        }
        S::Atom(s) => match s.as_str() {
            "true" => Ok(ST::Bool(true)),
            "false" => Ok(ST::Bool(false)),
            n => n
                .parse::<i64>()
                .and_then(|x| Ok(ST::I64(x)))
                .map_err(Into::into),
        },
    }
}

pub fn output_allowed(s: &str) -> bool {
    interpret(&S::parse_str(s).expect("parse error"), false, false).unwrap() == ST::Bool(true)
}

pub fn validate(s: &str) -> Result<(), Error> {
    match interpret(&S::parse_str(s)?, true, true) {
        Ok(ST::Bool(_)) => Ok(()),
        Err(e) => Err(e),
        _ => bail!("result type mismatch"),
    }
}
