---
layout: post
redirect_from:
  - /blog/2016/04/03/arc-050-a/
date: 2016-04-03T03:35:15+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "brainfuck", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc050/tasks/arc050_a" ]
---

# AtCoder Regular Contest 050 A - 大文字と小文字

言語テスト以降、初めて私以外のbrainfuckerを観測した回。めでたい。(<https://beta.atcoder.jp/contests/arc050/submissions/682671>)

## 実装

golfed, 100B。
`No`と`Yes`の生成の2行をまとめてやればまだ縮みそう。

``` brainfuck
, A
>,[<+>>+<-] space
, a
[<->-]
+
<
[>>[>+++++>+++++++<<--]>-<<-] No
>[>[>+++>+++>++++<<<-]++++++[>->+>--<<<-]] Yes
>[-.>],. newline
```
