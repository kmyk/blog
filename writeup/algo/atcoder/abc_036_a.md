---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-036-a/
  - /blog/2016/04/09/abc-036-a/
date: 2016-04-09T22:16:38+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc036/tasks/abc036_a" ]
---

# AtCoder Beginner Contest 036 A - お茶

<!-- {% raw %} -->

いつもの言語でやろうとしたら$A, B \le 1000$に殺された。
多倍長除算は用意してなかった。

## solution

$\lceil \frac{b}{a} \rceil$.

## implementation

### 20byte awk

hanada3355氏のが元。

``` awk
$0=int(($2+$1-1)/$1)
```

### rust

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3, Oliver Schneider, MIT License
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// ' }}}

fn main() {
    let (a, b): (i32, i32) = (read!(), read!());
    println!("{}", (b + a - 1) / a);
}
```

<!-- {% endraw %} -->
