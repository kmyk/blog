---
layout: post
redirect_from:
  - /writeup/golf/atcoder/abc-057-a/
  - /blog/2017/03/27/abc-057-a/
date: "2017-03-27T13:08:32+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "golf", "awk" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc057/tasks/abc057_a" ]
---

# AtCoder Beginner Contest 057: A - Remaining Time

awk $15$byteを提出した。

``` awk
$0=($1+$2)%24""
```

## 反省

hanada3355さんのそれが暫定最短(<https://beta.atcoder.jp/contests/abc057/submissions/1180872>)であった。

私の提出の`""`を`a`で置き換えたもの。
真偽値として真にするため、整数`0`に空文字列`""`を文字列連結して文字列`"0"`にしているのだが、未使用の変数`a`も空文字列として評価されるためこれを使っているようだ。

頻出テクだろうし一度は見ているはずだが、まったく記憶になかった。
