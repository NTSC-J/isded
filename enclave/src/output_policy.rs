mod s_expression;
use s_expression::S;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::prelude::v1::*;
extern crate chrono;
use output_policy::chrono::prelude::*;

enum OutputPolicy {
    Before(DateTime<Utc>),
    After(DateTime<Utc>),
    Count(u64),
    And(Vec<OutputPolicy>),
    Or(Vec<OutputPolicy>),
    Not(Box<OutputPolicy>)
}
impl OutputPolicy {
    pub fn parse_str(s: &str) -> std::io::Result<OutputPolicy> {
        let expr = S::parse_str(s);
        OutputPolicy::parse(&expr)
    }
    pub fn parse(expr: &S) -> std::io::Result<OutputPolicy> {
        fn data_error(msg: &str) -> std::io::Result<OutputPolicy> {
            Err(Error::new(ErrorKind::InvalidData, msg))
        }
        match expr {
            S::List(v) => {
                if let Some(S::Atom(s)) = v.get(0) {
                    match s.as_str() {
                        "before" => {
                            if let Some(S::Atom(time)) = v.get(1) {
                                Ok(OutputPolicy::Before(DateTime::parse_from_rfc3339(time)?))
                            } else {
                                data_error("unexpected nil")
                            }
                        }
                        "after" => {
                            if let Some(S::Atom(time)) = v.get(1) {
                                Ok(OutputPolicy::After(DateTime::parse_from_rfc3339(time)?))
                            } else {
                                data_error("unexpected nil")
                            }
                        }
                        "count" => {
                            if let Some(S::Atom(count)) = v.get(1) {
                                if let Ok(c) = count.parse() {
                                    Ok(OutputPolicy::Count(c))
                                } else {
                                    data_error(&format!("cannot parse {} as u64", count))
                                }
                            } else {
                                data_error("unexpected nil")
                            }
                        }
                        "and" => {
                            let ps = Vec::<OutputPolicy>::new();
                            for p in v.iter().skip(1).map(OutputPolicy::parse) {
                                match p {
                                    Ok(p_) => ps.push(p_),
                                    Err(_) => return p
                                }
                            }
                            Ok(OutputPolicy::And(ps))
                        }
                        "or" => {
                            let ps = Vec::<OutputPolicy>::new();
                            for p in v.iter().skip(1).map(OutputPolicy::parse) {
                                match p {
                                    Ok(p_) => ps.push(p_),
                                    Err(_) => return p
                                }
                            }
                            Ok(OutputPolicy::Or(ps))
                        }
                        "not" => {
                            if let Some(e) = v.get(1) {
                                if let Ok(p) = OutputPolicy::parse(e) {
                                    return Ok(OutputPolicy::Not(Box::new(p)))
                                }
                            }
                            data_error("unexpected nil")
                        }
                    }
                } else {
                    data_error("unexpected nil")
                }
            },
            _ => data_error(&format!("unexpected {:?}", expr))
        }
    }
}

