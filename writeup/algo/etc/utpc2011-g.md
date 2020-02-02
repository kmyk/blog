---
layout: post
alias: "/blog/2017/12/25/utpc2011-g/"
title: "東京大学プログラミングコンテスト2011: G. プログラミングコンテストチャレンジブック"
date: "2017-12-25T19:10:59+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj" ]
---

-   <http://www.utpc.jp/2011/problems/triangle.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_7>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2265>

## solution

$(a, b, c)$が三角形の$3$辺を成すためには$a \le b \le c$として$a + b \gt c$が必要十分。
とりあえず数列$a$をsortし降順とする。$a\_0 \ge a\_1 + a\_2$なら$a\_0$はどうやっても使えないので再帰的に無視してよい。愚直には$(a\_0, a\_1, a\_2)$を三角形として採用したい。
しかしこれを提出するとWAであるため、$a\_0, a\_1, a\_2, a\_3, a\_4, a\_5$などが$(a\_0, a\_1, a\_2), (a\_3, a\_4, a\_5)$以外の分割になりうる場合があることが分かる。適当に大きめに取って全探索すればよし。$O(N \log N + k!)$。

## implementation

``` python
#!/usr/bin/env python3
import itertools

def greedy(a):
    while len(a) >= 3:
        if a[-3] + a[-2] > a[-1]:
            return a.pop() + a.pop() + a.pop()
        else:
            a.pop()

def bruteforce(a):
    while len(a) >= 3 and a[-3] + a[-2] <= a[-1]:
        a.pop()
    result = 0
    for b in itertools.combinations(a[- 10 :], 6):
        for partition in itertools.combinations(range(6), 3):
            c, d = [], []
            for i in range(6):
                if i in partition:
                    c += [ b[i] ]
                else:
                    d += [ b[i] ]
            if c[0] + c[1] > c[2] and d[0] + d[1] > d[2]:
                result = max(result, sum(b))
    return result

def solve(preserved_a):
    result = 0

    # greedy
    a = list(preserved_a)
    x = greedy(a)
    y = greedy(a)
    if x is not None and y is not None:
        result = max(result, x + y)

    # bruteforce
    a = list(preserved_a)
    x = bruteforce(a)
    result = max(result, x)

    return result

n = int(input())
a = sorted([ int(input()) for _ in range(n) ])
result = solve(a)
print(result)
```
