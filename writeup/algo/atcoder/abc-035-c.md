---
layout: post
redirect_from:
  - /blog/2016/03/28/abc-035-c/
date: 2016-03-28T00:43:11+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "rust", "imos-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc035/tasks/abc035_c" ]
---

# AtCoder Regular Contest 035 C - オセロ

<!-- {% raw %} -->

atcoderの提出結果表示でのrustのhighlightがlifetimeの`'`で混乱してるの見て笑ってたら、この記事生成してるblog engineが`{{`を制御文字と混乱して死んでた。

## 解法

区間addの変分だけ更新して、最後に累積和しながら舐める。つまり[imos法](http://imoz.jp/algorithms/imos_method.html)そのまま。

## 実装

-   vectorの使用感は良い。
-   `let (n, q) = read!();` とは(今はまだ)書けないらしい。
-   `usize`は推論してくれなかった。

``` rust
// #[macro_use] extern crate text_io; {{{
// https://crates.io/crates/text_io/0.1.3, Oliver Schneider, MIT License
macro_rules! read( () => { read!("{}") }; ($text:expr) => {{ let value; scan!($text, value); value }}; ($text:expr, $input:expr) => {{ let value; scan!($input => $text, value); value }}; );
macro_rules! scan( ($text:expr, $($arg:ident),*) => { scan!(std::io::stdin().bytes().map(|c| c.unwrap()) => $text, $($arg),*) }; ($input:expr => $text:expr, $($arg:ident),*) => {{ use std::io::Read; use std::str::FromStr; /* typesafe macros :) */ let text: &'static str = $text; let stdin: &mut Iterator<Item = u8> = &mut ($input); let mut text = text.bytes(); $( loop { match text.next() { Some(b'{') => match text.next() { Some(b'{') => assert_eq!(Some(b'{'), stdin.next()), Some(b'}') => { let s: Vec<u8> = match text.next() { Some(c) => stdin.take_while(|&ch| ch != c).collect(), None => stdin.take_while(|ch| !b"\t\r\n ".contains(ch)).collect(), }; let s = match std::str::from_utf8(&s) { Ok(s) => s, Err(e) => { let n = e.valid_up_to(); if n == 0 { panic!("input was not valid utf8: {:?}", s); } else { panic!("input was only partially valid utf8: \"{}\" followed by {:?}", std::str::from_utf8(&s[..n]).unwrap(), &s[n..]); } } }; $arg = FromStr::from_str(s).expect(&format!("could not parse {} as target type of {}", s, stringify!($arg))); break; } Some(_) => panic!("found bad curly brace"), None => panic!("found single open curly brace at the end of the format string"), }, Some(c) => assert_eq!(Some(c), stdin.next()), None => panic!("Bad read! format string: did not contain {{}}"), } })* for c in text { assert_eq!(Some(c), stdin.next()); } }}; );
// }}}

fn main() {
    let (n, q) = (read!(), read!());
    let mut a = vec![0; n+1];
    for _ in 0..q {
        let (l, r): (usize, usize)  = (read!(), read!());
        a[l-1] += 1;
        a[r  ] -= 1;
    }
    let mut acc = 0;
    for i in 0..n {
        acc += a[i];
        print!("{}", acc % 2);
    }
    println!("");
}
```

<!-- {% endraw %} -->
