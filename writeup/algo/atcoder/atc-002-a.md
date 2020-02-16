---
layout: post
alias: "/blog/2016/04/11/atc-002-a/"
date: 2016-04-11T06:48:02+09:00
tags: [ "competitive", "writeup", "atcoder", "atc", "bfs" ]
"target_url": [ "https://beta.atcoder.jp/contests/atc002/tasks/abc007_3" ]
---

# AtCoder Typical Contest 002 A - 幅優先探索

<!-- {% raw %} -->

過去の問題の使い回しによる変則的なurlがみどころ。
問題自体は良いもの。

## 実装

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3, Oliver Schneider, MIT License
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// ' }}}

use std::io::Read;
use std::collections::VecDeque;

pub const DIRS: [(i8, i8); 4] = [(-1, 0), (1, 0), (0, 1), (0, -1)];
fn main() {
    let (r,   c): (usize, usize) = (read!(), read!());
    let (sy, sx): (usize, usize) = (read!(), read!());
    let (gy, gx): (usize, usize) = (read!(), read!());
    let sy = sy - 1;
    let sx = sx - 1;
    let gy = gy - 1;
    let gx = gx - 1;
    let mut f = vec![vec!['\0'; c]; r];
    for y in 0..r {
        for x in 0..c {
            while f[y][x] != '.' && f[y][x] != '#' {
                f[y][x] = std::io::stdin().bytes().next().unwrap().unwrap() as char;
            }
        }
    }
    let mut q = VecDeque::new();
    q.push_back((sy, sx, 0 as i64));
    while ! q.is_empty() {
        let (y, x, d) = q.pop_front().unwrap();
        if (y, x) == (gy, gx) {
            println!("{}", d);
            break;
        }
        for i in 0..4 {
            let (dy, dx) = DIRS[i];
            let (ny, nx) = ((y as i8 + dy) as usize, (x as i8 + dx) as usize);
            if f[ny][nx] == '.' {
                f[ny][nx] = '#';
                q.push_back((ny, nx, d+1));
            }
        }
    }
}
```

<!-- {% endraw %} -->
