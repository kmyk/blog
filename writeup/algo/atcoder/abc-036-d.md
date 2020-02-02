---
layout: post
alias: "/blog/2016/04/09/abc-036-d/"
title: "AtCoder Beginner Contest 036 D - 塗り絵"
date: 2016-04-09T22:16:50+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc036/tasks/abc036_d" ]
---

<!-- {% raw %} -->

あまり言語を理解しないまま適当なcodingをしている。

## solution

木の上で再帰。それぞれの部分木に対し、その根を白/黒に塗ったときの全体の塗り方の数を求める。$O(N)$。

## implementation

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3, Oliver Schneider, MIT License
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// ' }}}
use std::usize;

pub const MOD: i64 = 1000000007;
fn rec(i: usize, prev: usize, g: & Vec<Vec<usize>>) -> (i64, i64) {
    let mut w = 1; // white
    let mut b = 1; // black
    for j in &g[i] {
        if *j != prev {
            let (nw, nb) = rec(*j, i, &g);
            w = w * (nw + nb) % MOD;
            b = b * nw % MOD;
        }
    }
    return (w, b);
}
fn main() {
    let n: usize = read!();
    let mut g = vec![vec![]; n];
    for _ in 0..n-1 {
        let (a, b): (usize, usize) = (read!(), read!());
        let (a, b) = (a-1, b-1);
        g[a].push(b);
        g[b].push(a);
    }
    let (w, b) = rec(0, usize::MAX, &g);
    println!("{}", (w + b) % MOD);
}
```

<!-- {% endraw %} -->
