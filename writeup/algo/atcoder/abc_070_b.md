---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-070-b/
  - /blog/2017/08/15/abc-070-b/
date: "2017-08-15T13:15:47+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc070/tasks/abc070_b" ]
---

# AtCoder Beginner Contest 070: B - Two Switches

sedの数値演算はいつもanagolの過去問からコピペしてる。

## implementation

``` sed
#!/bin/sed -f
:
s/[1-9]/&-/g
y/123456789/012345678/
s/-0/0----------/
t
s/00*/0/g
:1
/0 0-.*0 0-/s/^/+/
s/0-/0/g
t1
s/0.*//
s/^/0/
:2
s/+/<<123456789+01>/
s/\s*\(.\)<.*\1\(+*.\).*>/\2/
t2
```
