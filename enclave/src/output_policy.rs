use crate::jwtmc;
use crate::s_expression::{self, S};
use chrono::prelude::*;
use std::collections::BTreeMap;
use std::prelude::v1::*;
use thiserror::Error;
use serde::{Serialize, Deserialize};

const TIME_ADDR: (&str, u16) = ("jwtmc", 7777);

#[derive(Error, Debug)]
pub enum OutputPolicyError {
    #[error("Expected atom")]
    ExpectedAtomError,
    #[error("Argument number mismatch: expected {0}, got {1}")]
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
    #[error("Unexpected identifier: {0}")]
    UnexpectedIdentifierError(String),
    #[error(transparent)]
    JWTMCError(#[from] jwtmc::JWTMCError),
    #[error(transparent)]
    SExpressionError(#[from] s_expression::SExpressionError),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Failed to parse datetime")]
    ParseDateTimeError(chrono::format::ParseError), // doesn't implement std::error::Error
}
pub type OutputPolicyResult<T> = Result<T, OutputPolicyError>;

pub type Environment = BTreeMap<String, Value>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub enum Value {
    I64(i64),
    Bool(bool),
}

#[derive(Copy, Clone)]
struct InterpretMode {
    strict: bool,       // 文法チェックを行う
    dry_run: bool,      // MCP, TTP にアクセスしない
    init_env: bool,     // 環境初期化
}

fn interpret(expr: &S, env: Environment, mode: InterpretMode) -> OutputPolicyResult<(Value, Environment)> {
    match expr {
        S::List(v) => { // 組込み関数
            let name = match v.get(0) {
                Some(S::Atom(s)) => s,
                Some(_) => return Err(OutputPolicyError::ExpectedAtomError),
                None => return Err(OutputPolicyError::EmptyFunctionError),
            };
            interpret_fn(&name, &v[1..], env, mode)
        }
        S::Atom(s) => interpret_atom(&s, env, mode),
    }
}

fn interpret_atom(atom: &str, mut env: Environment, mode: InterpretMode) -> OutputPolicyResult<(Value, Environment)> {
    match atom {
        "true" => Ok((Value::Bool(true), env)),
        "false" => Ok((Value::Bool(false), env)),
        _ => {
            if let Ok(num) = atom.parse() {
                Ok((Value::I64(num), env))
            } else if mode.init_env {
                env.insert(atom.to_string(), Value::I64(0));
                Ok((Value::I64(0), env))
            } else if env.contains_key(atom) {
                Ok((*env.get(atom).unwrap(), env))
            } else {
                Err(OutputPolicyError::UnexpectedIdentifierError(atom.to_string()))
            }
        }
    }
}

fn interpret_args(args: &[S], mut env: Environment, mode: InterpretMode) -> OutputPolicyResult<(Vec<Value>, Environment)> {
    let mut values = Vec::new();
    for expr in args {
        let (value, newenv) = interpret(expr, env, mode)?;
        values.push(value);
        env = newenv;
    }
    Ok((values, env))
}

fn interpret_fn(name: &str, args: &[S], mut env: Environment, mode: InterpretMode) -> OutputPolicyResult<(Value, Environment)> {
    let test_argc = |argc| { // 引数の数をチェック
        if args.len() != argc {
            Err(OutputPolicyError::ArgumentNumberMismatchError(
                name.to_owned(),
                argc,
                args.len(),
            ))
        } else {
            Ok(())
        }
    };
    match name {
        "<" => { // I64 -> I64 -> Bool
            test_argc(2)?;
            let (args, env) = interpret_args(args, env, mode)?;
            match args[..] {
                [Value::I64(a), Value::I64(b)] => Ok((Value::Bool(a < b), env)),
                _ => Err(OutputPolicyError::FunctionError("<".to_string())),
            }
        }
        ">" => { // I64 -> I64 -> Bool
            test_argc(2)?;
            let (args, env) = interpret_args(args, env, mode)?;
            match args[..] {
                [Value::I64(a), Value::I64(b)] => Ok((Value::Bool(a > b), env)),
                _ => Err(OutputPolicyError::FunctionError(">".to_string())),
            }
        }
        "==" => { // a -> a -> Bool
            test_argc(2)?;
            let (args, env) = interpret_args(args, env, mode)?;
            match args[..] {
                [Value::I64(a), Value::I64(b)] => Ok((Value::Bool(a == b), env)),
                [Value::Bool(a), Value::Bool(b)] => Ok((Value::Bool(a == b), env)),
                _ => Err(OutputPolicyError::FunctionError("==".to_string())),
            }
        }
        "and" => { // [Bool] -> Bool, 短絡評価
            for expr in args {
                let (value, newenv) = interpret(expr, env, mode)?;
                env = newenv;
                match value {
                    Value::Bool(false) => return Ok((Value::Bool(false), env)),
                    Value::Bool(true) => (),
                    _ => return Err(OutputPolicyError::FunctionError("and".to_string())),
                }
            }
            Ok((Value::Bool(true), env))
        }
        "or" => { // [Bool] -> Bool, 短絡評価
            for expr in args {
                let (value, newenv) = interpret(expr, env, mode)?;
                env = newenv;
                match value {
                    Value::Bool(true) => return Ok((Value::Bool(true), env)),
                    Value::Bool(false) => (),
                    _ => return Err(OutputPolicyError::FunctionError("or".to_string()))
                }
            }
            Ok((Value::Bool(false), env))
        }
        "not" => { // Bool -> Bool
            test_argc(1)?;
            let (expr, env) = interpret(&args[0], env, mode)?;
            match expr {
                Value::Bool(b) => Ok((Value::Bool(!b), env)),
                _ => Err(OutputPolicyError::FunctionError("not".to_string())),
            }
        }
        "timevalue" => { // String -> I64
            test_argc(1)?;
            let s = match &args[0] {
                S::Atom(s) => s,
                _ => return Err(OutputPolicyError::ExpectedAtomError),
            };
            // オフセットが違ってもtimestampの起点は同一(Unix epoch)
            Ok((Value::I64(
                DateTime::<FixedOffset>::parse_from_rfc3339(&s)
                    .map_err(OutputPolicyError::ParseDateTimeError)?
                    .timestamp_millis()
            ), env))
        }
        "now" => { // I64
            test_argc(0)?;
            if mode.dry_run {
                Ok((Value::I64(0), env))
            } else {
                // 5.84億年間使える
                Ok((Value::I64(jwtmc::query_time(&TIME_ADDR)?.timestamp_millis()), env))
            }
        }
        "++" => { // I64 -> I64
            test_argc(1)?;
            let var = match &args[0] {
                S::Atom(s) => s.to_string(),
                _ => return Err(OutputPolicyError::ExpectedAtomError),
            };
            if mode.init_env {
                env.insert(var.clone(), Value::I64(0));
            }
            if mode.init_env || mode.dry_run {
                return Ok((Value::I64(0), env));
            }
            match env.get(&var) {
                None => Err(OutputPolicyError::InvalidVariableNameError),
                Some(Value::I64(x)) => {
                    let newx = Value::I64(x + 1);
                    env.insert(var, newx);
                    Ok((newx, env))
                }
                Some(_) => {
                    Err(OutputPolicyError::FunctionError("++".to_owned()))
                }
            }
        }
        _ => Err(OutputPolicyError::UnknownFunctionError(name.to_owned())),
    }
}

// 実際に評価を行う
pub fn evaluate(s: &str, env: Environment) -> OutputPolicyResult<(bool, Environment)> {
    let expr = S::parse_str(s)?;
    let mode = InterpretMode {
        strict: false,
        dry_run: false,
        init_env: false
    };
    match interpret(&expr, env, mode)? {
        (Value::Bool(b), newenv) => Ok((b, newenv)),
        _ => Err(OutputPolicyError::TypeError),
    }
}

// 文法のチェック
pub fn validate(s: &str) -> OutputPolicyResult<()> {
    let empty_env = Environment::new();
    match interpret(&S::parse_str(s)?, empty_env, InterpretMode {
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
    let empty_env = Environment::new();
    let (_, env) = interpret(&S::parse_str(s)?, empty_env, InterpretMode {
        strict: true,
        dry_run: true,
        init_env: true})?;
    Ok(env)
}
