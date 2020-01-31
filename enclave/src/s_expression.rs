use std::prelude::v1::*;
use std::vec::Vec;
use std::env;
use std::str::Chars;
use std::iter::Peekable;

#[derive(Debug)]
pub enum Token {
    LParen,
    RParen,
    Dot,
    Atom(String),
}
#[derive(Debug)]
pub struct Lexer<'a> {
    data: Peekable<Chars<'a>>
}
impl<'a> Lexer<'a> {
    pub fn new(s: &str) -> Lexer {
        Lexer{data: s.chars().peekable().clone()}
    }
}
impl<'a> Iterator for Lexer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        if let Some(c) = self.data.next() {
            match c {
                '(' => Some(Token::LParen),
                ')' => Some(Token::RParen),
                '.' => Some(Token::Dot),
                ' ' | '\t' | '\n' => self.next(),
                x => {
                    let mut atom = x.to_string();
                    loop {
                        if let Some(d) = self.data.peek() {
                            match d {
                                '(' | ')' | ' ' | '\t' | '\n' => return Some(Token::Atom(atom)),
                                _ => atom.push(self.data.next().unwrap()) // == d
                            }
                        } else {
                            return Some(Token::Atom(atom))
                        }
                    }
                }
            }
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum S {
    Atom(String),
    List(Vec<S>), // nilは空のリストになる
    Invalid(String)
}
impl S {
    pub fn parse_str(data: &str) -> S {
        S::parse(&mut Lexer::new(data).peekable())
    }
    pub fn parse(lexer: &mut Peekable<Lexer>) -> S {
        if let Some(l) = lexer.next() {
            match l {
                Token::LParen => S::get_list(lexer),
                Token::Atom(x) => S::Atom(x),
                _ => S::Invalid("unexpected token".to_string())
            }
        } else {
            S::Invalid("early EOF".to_string())
        }
    }
    fn get_list(lexer: &mut Peekable<Lexer>) -> S {
        let mut list = Vec::<S>::new();
        if let Some(car) = lexer.peek() {
            match car {
                Token::RParen => {
                    lexer.next(); // )
                    return S::List(list) // nil
                },
                _ => {
                    list.push(S::parse(lexer)); // car
                    if let Some(n) = lexer.peek() {
                        match n {
                            Token::Dot => {
                                lexer.next(); // .
                                match S::parse(lexer) { // cdr
                                    S::List(x) => {
                                        list.extend(x);
                                    },
                                    x => {
                                        list.push(x);
                                    }
                                }
                                match lexer.next() {
                                    Some(Token::RParen) => {},
                                    _ => list.push(S::Invalid("expected )".to_string()))
                                }
                            },
                            _ => {
                                match S::get_list(lexer) {
                                    S::List(cdr) => list.extend(cdr),
                                    x => list.push(x) // Invalid
                                }
                            }
                        }
                    } else {
                        return S::Invalid("early EOF in list".to_string())
                    }
                }
            }
        } else {
            return S::Invalid("early EOF in list".to_string())
        }
        S::List(list)
    }
}

