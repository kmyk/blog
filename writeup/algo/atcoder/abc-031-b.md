---
layout: post
redirect_from:
  - /blog/2015/11/21/abc-031-b/
date: 2015-11-21T23:09:38+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "awk" ]
---

# AtCoder Beginner Contest 031 B - 運動管理

awkを選んだ理由は特にない。

## [B - 運動管理](https://beta.atcoder.jp/contests/abc031/tasks/abc031_b) {#b}

``` awk
NR == 1 { l = $1; h = $2; }
NR == 2 { n = $1; }
NR >= 3 {
    if ($1 < l) print l - $1;
    else if (h < $1) print -1;
    else print 0;
}
```
