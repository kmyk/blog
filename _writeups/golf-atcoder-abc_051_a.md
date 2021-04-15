---
layout: post
redirect_from:
  - /writeup/golf/atcoder/abc_051_a/
  - /writeup/golf/atcoder/abc-051-a/
  - /blog/2017/01/07/abc-051-a/
date: "2017-01-07T22:12:30+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "golf", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc051/tasks/abc051_a" ]
---

# AtCoder Beginner Contest 051: A - Haiku

AtCoderはsedとbrainfuckが使えるので最高。

## implementation

``` sed
y/,/ /
```

``` brainfuck
,.,.,.,.,.,------------.>,.,.,.,.,.,.,.,<+[-.,+]
```

brainfuckは%20さんのを元に少し縮めたもの。
HaikuでなくてTankaなら違ってきただろうが今回は、`,.`の繰り返しはベタ書きが一番短いようだった。

---

# AtCoder Beginner Contest 051: A - Haiku

-   Sun Jan  8 16:03:51 JST 2017
    -   angelさんや%20さんがbrainfuckしてたので参加した
