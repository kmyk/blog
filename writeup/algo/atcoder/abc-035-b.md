---
layout: post
alias: "/blog/2016/03/28/abc-035-b/"
title: "AtCoder Regular Contest 035 B - ドローン"
date: 2016-03-28T00:01:40+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "rust" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc035/tasks/abc035_b" ]
---

<!-- {% raw %} -->

rust使ってみた。
言語的な部分はかなり良さそうなので、競技用途では標準ライブラリの充実度次第という印象。

しかし、atcoderに関して言えばc++にboostが追加されており、codeforcesやtopcoderではrustは使えないので、やはりc++の優位は変わらない。

## 解法

`?`以外を処理した後に、`?`の回数だけ望ましい方向に移動すればよい。
移動しないという選択肢はないため、原点に辿り付いた場合、遠ざかる移動が発生することに注意。

## 実装

現在のrustの標準にはまともな入力取得関数がない。

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// }}}

fn main() {
    let s: String = read!("{}\n");
    let t: i8 = read!("{}\n");
    let mut x: i64 = 0;
    let mut y: i64 = 0;
    let mut q: i64 = 0;
    for c in s.chars() {
        match c {
            'U' => y -= 1,
            'D' => y += 1,
            'R' => x += 1,
            'L' => x -= 1,
            '?' => q += 1,
            _   => panic!(),
        }
    }
    let l = x.abs() + y.abs();
    let ans = match t {
        1 => l + q,
        2 if l < q => (q - l) % 2,
        2          =>  l - q,
        _ => panic!(),
    };
    println!("{}", ans);
}
```

<!-- {% endraw %} -->
