---
layout: post
alias: "/blog/2016/04/22/arc-051-a/"
date: 2016-04-22T17:55:01+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc051/tasks/arc051_a" ]
---

# AtCoder Regular Contest 051 A - 塗り絵

<!-- {% raw %} -->

## solution

それぞれ$4$箇所確認すればよい。

## implementation

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3, Oliver Schneider, MIT License
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// ' }}}

fn sq(x: i64) -> i64 {
    return x * x;
}

fn main() {
    let (xc, yc, r): (i64, i64, i64) = (read!(), read!(), read!());
    let (xa, ya, xb, yb): (i64, i64, i64, i64) = (read!(), read!(), read!(), read!());
    let mut p = false;
    for (dx, dy) in vec![ (0, -r), (0, r), (r, 0), (-r, 0) ] {
        let x = xc + dx;
        let y = yc + dy;
        if x < xa || xb < x || y < ya || yb < y {
            p = true;
        }
    }
    let mut q = false;
    for x in vec![ xa, xb ] {
        for y in vec![ ya, yb ] {
            if sq(r) < sq(x - xc) + sq(y - yc) {
                q = true;
            }
        }
    }
    println!("{}", if p { "YES" } else { "NO" });
    println!("{}", if q { "YES" } else { "NO" });
}
```

<!-- {% endraw %} -->
