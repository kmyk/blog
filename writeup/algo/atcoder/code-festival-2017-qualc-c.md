---
layout: post
alias: "/blog/2018/01/01/code-festival-2017-qualc-c/"
date: "2018-01-01T12:14:04+09:00"
tags: [ "competitive", "writeup", "codefestival", "palindrome" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualc/tasks/code_festival_2017_qualc_c" ]
---

# CODE FESTIVAL 2017 qual C: C - Inserting 'x'

## solution

両側から見ていって、両側同じならそれでよし、片側にのみ`x`があれば追加、`x`がないのに異なれば失敗。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
s = input()
l = 0
r = len(s) - 1
cnt = 0
while l < r:
    if s[l] == s[r]:
        l += 1
        r -= 1
    elif s[l] == 'x':
        cnt += 1
        l += 1
    elif s[r] == 'x':
        cnt += 1
        r -= 1
    else:
        cnt = -1
        break
print(cnt)
```
