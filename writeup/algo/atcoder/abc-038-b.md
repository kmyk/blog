---
layout: post
alias: "/blog/2016/05/28/abc-038-b/"
date: 2016-05-28T23:00:02+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "regex", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc038/tasks/abc038_b" ]
---

# AtCoder Beginner Contest 038 B - ディスプレイ

解答がA問題とほぼ同じなあたり、すごく楽しいですね

``` sed
#!/bin/sed -f
N
/\b\(\w\+\)\b.*\n.*\b\1\b/ s/.*/YES/
t
s/.*/NO/
```
