---
layout: post
alias: "/blog/2016/05/01/hackerrank-world-codesprint-april-kmp-problem/"
title: "HackerRank World Codesprint April: Yet Another KMP Problem"
date: 2016-05-01T12:20:55+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "greedy", "construct" ]
---

I don't dislike this problem, but the problem statement is too complicated.

## problem

整数$x_a, x_b, x_c, \dots, x_z$が与えられる。
文字$\gamma$をちょうど$x\_\gamma$個含むような文字列$S$で、それからKMP法で作られる表$T_S$を考え、その総和と文字列の対$(\Sigma\_{i \le \|S\|} (T_S)\_i, S)$が辞書順最小になるような$S$を答えよ。

## solution

Construct the string almost greedy. $O(N)$.

Let $c_i$ is the $i$-th character in the result string (the leftmost is $0$).
The $c_0$ should be one which is least frequently appeared.
The $c\_{i+1}$ can be decided greedily, use the alphabetically smallest character which can be used yet.
But you cannot use as $(c\_{i+1}, c\_{i+2}) = (c_0, c_1)$, so in such a case, you need to use the $2$-nd alphabetically smallest character as $c\_{i+2}$.
The construction is done by above, because the $c_0$ is the least frequent one.

## implementation

``` c++
#!/usr/bin/env python3
import string
xs = list(map(int,input().split()))
ys = map(list,filter(lambda p: p[0] != 0, zip(xs, string.ascii_lowercase)))
ys = list(sorted(ys))
c = ys[0][1]
ys[0][0] -= 1
if ys[0][0] == 0:
    del ys[0]
ys = list(sorted(ys, key=lambda p: p[1]))
s = [c]
while ys:
    i = 0
    if len(s) >= 2 and len(ys) >= 2 and s[0] == s[1] == s[-1] == c == ys[i][1]:
        i = 1
    s.append(ys[i][1])
    ys[i][0] -= 1
    if ys[i][0] == 0:
        del ys[i]
print(*s, sep='')
```
