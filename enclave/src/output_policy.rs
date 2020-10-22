use crate::jwtmc;
use crate::s_expression::{self, S};
use chrono::prelude::*;
use std::collections::HashMap;
use std::prelude::v1::*;
use thiserror::Error;

const MC_ADDR: (&str, u16) = ("localhost", 7777);
const TIME_ADDR: (&str, u16) = ("localhost", 7777);

#[derive(Error, Debug)]
pub enum OutputPolicyError {
    #[error("Expected atom")]
    ExpectedAtomError,
    #[error("Argument number mismatch")]
    ArgumentNumberMismatchError(String, usize, usize),
    #[error("Function without its name")]
    EmptyFunctionError,
    #[error("Type mismatch")]
    TypeError,
    #[error("Some error in function {0}")]
    FunctionError(String),
    #[error("Unknown function: {0}")]
    UnknownFunctionError(String),
    #[error(transparent)]
    JWTMCError(#[from] jwtmc::JWTMCError),
    #[error(transparent)]
    SExpressionError(#[from] s_expression::SExpressionError),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    ParseDateTimeError(chrono::format::ParseError), // doesn't implement std::error::Error
}
pub type OutputPolicyResult<T> = Result<T, OutputPolicyError>;

// TODO
fn get_trusted_time() -> OutputPolicyResult<DateTime<Utc>> {
    Ok(jwtmc::query_time(&TIME_ADDR)?)
}
fn get_monotonic_counter() -> OutputPolicyResult<i64> {
    Ok(0)
}

pub type Environment<'a> = HashMap<&'a str, i64>;

#[derive(Debug, PartialEq)]
pub enum ST {
    I64(i64),
    Bool(bool),
}

// strict: 文法チェックを行う
// dry_run: MEにアクセスしない
pub fn interpret(expr: &S, strict: bool, dry_run: bool) -> OutputPolicyResult<ST> {
    let interpret_ = |e| interpret(e, strict, dry_run);
    match expr {
        S::List(v) => {
            let f = match v.get(0) {
                Some(S::Atom(s)) => s,
                Some(_) => return Err(OutputPolicyError::ExpectedAtomError),
                None => return Err(OutputPolicyError::EmptyFunctionError),
            };
            let test_argc = |argc| {
                if v.len() - 1 != argc {
                    Err(OutputPolicyError::ArgumentNumberMismatchError(
                        f.to_owned(),
                        argc,
                        v.len(),
                    ))
                } else {
                    Ok(())
                }
            };
            let test_bool = || {
                for e in v.iter().skip(1).map(interpret_) {
                    match e {
                        Ok(ST::Bool(_)) => (),
                        _ => return Err(OutputPolicyError::TypeError),
                    }
                }
                Ok(())
            };
            match f.as_str() {
                // <: I64 -> I64 -> Bool
                "<" => {
                    test_argc(2)?;
                    match (interpret_(&v[1]), interpret_(&v[2])) {
                        (Ok(ST::I64(a)), Ok(ST::I64(b))) => Ok(ST::Bool(a < b)),
                        _ => return Err(OutputPolicyError::FunctionError("<".to_string())),
                    }
                }
                // >: I64 -> I64 -> Bool
                ">" => {
                    test_argc(2)?;
                    match (interpret_(&v[1]), interpret_(&v[2])) {
                        (Ok(ST::I64(a)), Ok(ST::I64(b))) => Ok(ST::Bool(a > b)),
                        _ => return Err(OutputPolicyError::FunctionError(">".to_string())),
                    }
                }
                // ==: a -> a -> Bool
                "==" => {
                    test_argc(2)?;
                    match (interpret_(&v[1]), interpret_(&v[2])) {
                        (Ok(ST::I64(a)), Ok(ST::I64(b))) => Ok(ST::Bool(a == b)),
                        (Ok(ST::Bool(a)), Ok(ST::Bool(b))) => Ok(ST::Bool(a == b)),
                        _ => return Err(OutputPolicyError::FunctionError("==".to_string())),
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
                            Ok(ST::I64(_)) => {
                                return Err(OutputPolicyError::FunctionError("and".to_string()))
                            }
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
                            Ok(ST::I64(_)) => {
                                return Err(OutputPolicyError::FunctionError("or".to_string()))
                            }
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
                        Ok(ST::I64(_)) => {
                            return Err(OutputPolicyError::FunctionError("not".to_string()))
                        }
                        Ok(ST::Bool(b)) => Ok(ST::Bool(!b)),
                    }
                }
                // timevalue: String -> I64
                "timevalue" => {
                    test_argc(1)?;
                    let s = match v.get(1) {
                        Some(S::Atom(s)) => s,
                        Some(_) => return Err(OutputPolicyError::ExpectedAtomError),
                        None => {
                            return Err(OutputPolicyError::FunctionError("timevalue".to_string()))
                        }
                    };
                    // オフセットが違ってもtimestampの起点は同一(Unix epoch)
                    Ok(ST::I64(
                        DateTime::<FixedOffset>::parse_from_rfc3339(&s)
                            .map_err(|e| OutputPolicyError::ParseDateTimeError(e))?
                            .timestamp_millis(),
                    ))
                }
                // now: I64 （参照透過でない）
                "now" => {
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
                _ => Err(OutputPolicyError::UnknownFunctionError(f.to_owned())),
            }
        }
        S::Atom(s) => match s.as_str() {
            "true" => Ok(ST::Bool(true)),
            "false" => Ok(ST::Bool(false)),
            n => Ok(ST::I64(n.parse()?)),
        },
    }
}

pub fn output_allowed(s: &str) -> bool {
    interpret(&S::parse_str(s).expect("parse error"), false, false).unwrap() == ST::Bool(true)
}

pub fn validate(s: &str) -> OutputPolicyResult<()> {
    match interpret(&S::parse_str(s)?, true, true) {
        Ok(ST::Bool(_)) => Ok(()),
        Err(e) => Err(e),
        _ => Err(OutputPolicyError::TypeError),
    }
}
