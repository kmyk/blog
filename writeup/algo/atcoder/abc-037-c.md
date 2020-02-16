---
layout: post
alias: "/blog/2016/05/14/abc-037-c/"
date: 2016-05-14T20:01:05+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc037/tasks/abc037_c" ]
---

# AtCoder Beginner Contest 037 C - 総和

<!-- {% raw %} -->

$n-k+1$を忘れていたWAが生えた。

## solution

$\Sigma\_{0 \le i \lt n} a_i \cdot \min \\{ k, n-k+1, i+1, n-i \\}$. $O(N)$.

## implementation

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3, Oliver Schneider, MIT License
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// ' }}}

use std::cmp::min;
fn main() {
    let (n, k): (i64, i64) = (read!(), read!());
    let mut ans: i64 = 0;
    for i in 0..n {
        let a: i64 = read!();
        let t = min(k, min(n-k+1, min(i+1, n-i)));
        ans += a * t;
    }
    println!("{}", ans);
}
```

<!-- {% endraw %} -->
