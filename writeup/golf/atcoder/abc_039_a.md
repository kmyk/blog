---
layout: post
redirect_from:
  - /writeup/golf/atcoder/abc-039-a/
  - /blog/2016/06/11/abc-039-a/
date: 2016-06-11T23:00:01+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "awk", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc039/tasks/abc039_a" ]
---

# AtCoder Beginner Contest 039 A - 高橋直体

## implementation

### awk 23byte

``` awk
$0=2*($1*($2+$3)+$2*$3)
```
