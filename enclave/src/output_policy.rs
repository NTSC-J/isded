use crate::jwtmc;
use crate::s_expression::{self, S};
use chrono::prelude::*;
use std::collections::HashMap;
use std::prelude::v1::*;
use thiserror::Error;
use serde::{Serialize, Deserialize};

const MC_ADDR: (&str, u16) = ("jwtmc", 7777);
const TIME_ADDR: (&str, u16) = ("jwtmc", 7777);

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
    #[error("Invalid variable name")]
    InvalidVariableNameError,
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

pub type Environment = HashMap<String, Value>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Value {
    I64(i64),
    Bool(bool),
}

#[derive(Clone)]
struct InterpretMode {
    strict: bool,       // 文法チェックを行う
    dry_run: bool,      // MCP, TTP にアクセスしない
    init_env: bool,     // 環境初期化
}

fn interpret(expr: &S, env: &Environment, mode: InterpretMode) -> OutputPolicyResult<(Value, Environment)> {
    let intp = |expr, env| interpret(expr, env, mode.clone());

    match expr {
        S::List(v) => { // 組込み関数
            let f = match v.get(0) { // 関数名を取り出す
                Some(S::Atom(s)) => s,
                Some(_) => return Err(OutputPolicyError::ExpectedAtomError),
                None => return Err(OutputPolicyError::EmptyFunctionError),
            };
            let test_argc = |argc| { // 引数の数をチェック
                if v.len() != argc + 1 {
                    Err(OutputPolicyError::ArgumentNumberMismatchError(
                        f.to_owned(),
                        argc,
                        v.len(),
                    ))
                } else {
                    Ok(())
                }
            };
            let test_bool = || { // 引数の型が全て Bool かどうかチェック
                for e in v.iter().skip(1).map(|expr| intp(expr, env)) {
                    match e?.0 {
                        Value::Bool(_) => (),
                        _ => return Err(OutputPolicyError::TypeError),
                    }
                }
                Ok(())
            };
            let intp_args = || -> OutputPolicyResult<(Vec<Value>, Environment)> { // 引数を順番に評価して結果の配列と環境を返す。もっと関数型っぽく書きたい
                let mut res = Vec::new();
                let mut env = env.clone();
                for expr in v.iter().skip(1) {
                    let (r, e) = interpret(expr, &env, mode.clone())?;
                    env = e;
                    res.push(r);
                }
                Ok((res, env))
            };
            match f.as_str() {
                "<" => { // I64 -> I64 -> Bool
                    test_argc(2)?;
                    let (exprs, env) = intp_args()?;
                    match exprs[..] {
                        [Value::I64(a), Value::I64(b)] => Ok((Value::Bool(a < b), env)),
                        _ => return Err(OutputPolicyError::FunctionError("<".to_string())),
                    }
                }
                ">" => { // I64 -> I64 -> Bool
                    test_argc(2)?;
                    let (exprs, env) = intp_args()?;
                    match exprs[..] {
                        [Value::I64(a), Value::I64(b)] => Ok((Value::Bool(a > b), env)),
                        _ => return Err(OutputPolicyError::FunctionError(">".to_string())),
                    }
                }
                "==" => { // a -> a -> Bool
                    test_argc(2)?;
                    let (exprs, env) = intp_args()?;
                    match exprs[..] {
                        [Value::I64(a), Value::I64(b)] => Ok((Value::Bool(a == b), env)),
                        [Value::Bool(a), Value::Bool(b)] => Ok((Value::Bool(a == b), env)),
                        _ => return Err(OutputPolicyError::FunctionError("==".to_string())),
                    }
                }
                "and" => { // [Bool] -> Bool, 短絡評価
                    if mode.strict {
                        test_bool()?;
                    }
                    let (exprs, env) = intp_args()?;
                    for expr in exprs {
                        match expr {
                            Value::I64(_) => {
                                return Err(OutputPolicyError::FunctionError("and".to_string()))
                            }
                            Value::Bool(false) => return Ok((Value::Bool(false), env)),
                            Value::Bool(true) => (),
                        }
                    }
                    Ok((Value::Bool(true), env))
                }
                "or" => { // [Bool] -> Bool, 短絡評価
                    if mode.strict {
                        test_bool()?;
                    }
                    let (exprs, env) = intp_args()?;
                    for expr in exprs {
                        match expr {
                            Value::I64(_) => {
                                return Err(OutputPolicyError::FunctionError("or".to_string()))
                            }
                            Value::Bool(true) => return Ok((Value::Bool(true), env)),
                            Value::Bool(false) => (),
                        }
                    }
                    Ok((Value::Bool(false), env))
                }
                "not" => { // Bool -> Bool
                    test_argc(1)?;
                    test_bool()?;
                    let (expr, env) = intp(&v[1], env)?;
                    match expr {
                        Value::I64(_) => {
                            return Err(OutputPolicyError::FunctionError("not".to_string()))
                        }
                        Value::Bool(b) => Ok((Value::Bool(!b), env)),
                    }
                }
                "timevalue" => { // String -> I64
                    test_argc(1)?;
                    let s = match &v[1] {
                        S::Atom(s) => s,
                        _ => return Err(OutputPolicyError::ExpectedAtomError),
                    };
                    // オフセットが違ってもtimestampの起点は同一(Unix epoch)
                    Ok((Value::I64(
                        DateTime::<FixedOffset>::parse_from_rfc3339(&s)
                            .map_err(|e| OutputPolicyError::ParseDateTimeError(e))?
                            .timestamp_millis()
                    ), env.clone()))
                }
                "now" => { // I64
                    test_argc(0)?;
                    if mode.dry_run {
                        Ok((Value::I64(0), env.clone()))
                    } else {
                        // 5.84億年間使える
                        Ok((Value::I64(jwtmc::query_time(&TIME_ADDR)?.timestamp_millis()), env.clone()))
                    }
                }
                "++" => { // I64 -> I64
                    test_argc(1)?;
                    let var = match &v[1] {
                        S::Atom(s) => s.to_string(),
                        _ => return Err(OutputPolicyError::InvalidVariableNameError),
                    };
                    let mut env = env.clone();
                    if mode.init_env {
                        env.insert(var.clone(), Value::I64(0));
                    }
                    if mode.init_env || mode.dry_run {
                        return Ok((Value::I64(0), env));
                    }
                    match env.get(&var) {
                        None => return Err(OutputPolicyError::InvalidVariableNameError),
                        Some(Value::I64(x)) => {
                            let newx = Value::I64(x + 1);
                            env.insert(var, newx.clone());
                            Ok((newx, env))
                        }
                        Some(_) => {
                            Err(OutputPolicyError::FunctionError("++".to_owned()))
                        }
                    }
                }
                _ => Err(OutputPolicyError::UnknownFunctionError(f.to_owned())),
            }
        }
        S::Atom(s) => match s.as_str() {
            "true" => Ok((Value::Bool(true), env.clone())),
            "false" => Ok((Value::Bool(false), env.clone())),
            n => {
                let mut env = env.clone();
                if let Ok(nu) = n.parse() {
                    Ok((Value::I64(nu), env))
                } else if mode.init_env {
                    env.insert(n.to_string(), Value::I64(0));
                    Ok((Value::I64(0), env))
                } else if env.contains_key(n) {
                    Ok((env.get(n).unwrap().clone(), env))
                } else {
                    Err(OutputPolicyError::InvalidVariableNameError)
                }
            }
        },
    }
}

// 実際に評価を行う
pub fn evaluate(s: &str, env: &mut Environment) -> bool {
    if let Ok(e) = S::parse_str(s) {
        if let Ok((Value::Bool(true), newenv)) = interpret(&e, env, InterpretMode {
            strict: false,
            dry_run: false,
            init_env: false}) {
            *env = newenv;
            return true;
        }
    }
    false
}

// 文法のチェック
pub fn validate(s: &str) -> OutputPolicyResult<()> {
    let empty_env = HashMap::new();
    match interpret(&S::parse_str(s)?, &empty_env, InterpretMode {
        strict: true,
        dry_run: true,
        init_env: true}) {
        Ok((Value::Bool(_), _)) => Ok(()),
        Ok((_, _)) => Err(OutputPolicyError::TypeError),
        Err(e) => Err(e),
    }
}

// 変数を初期化
pub fn init_env(s: &str) -> OutputPolicyResult<Environment> {
    let empty_env = HashMap::new();
    let (_, env) = interpret(&S::parse_str(s)?, &empty_env, InterpretMode {
        strict: true,
        dry_run: true,
        init_env: true})?;
    Ok(env)
}
