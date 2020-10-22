use std::iter::Peekable;
use std::prelude::v1::*;
use std::str::Chars;
use std::vec::Vec;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SExpressionError {
    #[error("Unexpected Token: {0:#?}")]
    UnexpectedTokenError(Token),
    #[error("Early EOF")]
    EarlyEOFError,
    #[error("Expected )")]
    RParenNotFoundError,
}
pub type SExpressionResult<T> = Result<T, SExpressionError>;

#[derive(Debug, PartialEq)]
pub enum Token {
    LParen,
    RParen,
    Dot,
    Atom(String),
}
#[derive(Debug)]
pub struct Lexer<'a> {
    data: Peekable<Chars<'a>>,
}
impl<'a> Lexer<'a> {
    pub fn new(s: &str) -> Lexer {
        Lexer {
            data: s.chars().peekable().clone(),
        }
    }
}
impl<'a> Iterator for Lexer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        self.data.next().and_then(|c| match c {
            '(' => Some(Token::LParen),
            ')' => Some(Token::RParen),
            '.' => Some(Token::Dot),
            ' ' | '\t' | '\n' => self.next(),
            c => {
                let mut atom = c.to_string();
                loop {
                    match self.data.peek() {
                        Some(&d) if "() \t\n".contains(d) => return Some(Token::Atom(atom)),
                        None => return Some(Token::Atom(atom)),
                        Some(_) => atom.push(self.data.next().unwrap()), // == d
                    }
                }
            }
        })
    }
}

#[derive(Debug)]
pub enum S {
    Atom(String),
    List(Vec<S>), // nilは空のリストになる
}
impl S {
    pub fn parse_str(data: &str) -> SExpressionResult<S> {
        S::parse(&mut Lexer::new(data).peekable())
    }
    pub fn parse(lexer: &mut Peekable<Lexer>) -> SExpressionResult<S> {
        if let Some(l) = lexer.next() {
            match l {
                Token::LParen => S::get_list(lexer),
                Token::Atom(x) => Ok(S::Atom(x)),
                _ => Err(SExpressionError::UnexpectedTokenError(l)),
            }
        } else {
            Err(SExpressionError::EarlyEOFError)
        }
    }
    fn get_list(lexer: &mut Peekable<Lexer>) -> SExpressionResult<S> {
        let mut list = Vec::<S>::new();
        match lexer.peek() {
            Some(Token::RParen) => {
                lexer.next(); // )
                              // nil
            }
            Some(_) => {
                list.push(S::parse(lexer)?); // car
                match lexer.peek() {
                    Some(Token::Dot) => {
                        lexer.next(); // .
                        match S::parse(lexer) {
                            // cdr
                            Ok(S::List(x)) => list.extend(x),
                            Ok(x) => list.push(x),
                            e => return e,
                        }
                        if lexer.next() != Some(Token::RParen) {
                            return Err(SExpressionError::RParenNotFoundError);
                        }
                    }
                    Some(_) => {
                        match S::get_list(lexer) {
                            Ok(S::List(cdr)) => list.extend(cdr),
                            Ok(x) => list.push(x), // Invalid
                            e => return e,
                        }
                    }
                    None => return Err(SExpressionError::EarlyEOFError),
                }
            }
            None => return Err(SExpressionError::EarlyEOFError),
        }
        Ok(S::List(list))
    }
}
