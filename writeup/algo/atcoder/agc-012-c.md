---
layout: post
alias: "/blog/2017/08/02/agc-012-c/"
date: "2017-08-02T14:28:01+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc012/tasks/agc012_c" ]
---

# AtCoder Grand Contest 012: C - Tautonym Puzzle

## solution

列への操作で良い部分列の数$k$を$k \mapsto k + 1$とするものと$k \mapsto 2k$とするものをそれぞれ作る。$O(\log N)$。

簡単のため空列は良い文字列であるとする。$N$の代わりに$N + 1$が与えられたと思えばよい。
任意の列に対してそのような操作を考えるのは面倒なので、列$\gamma$は$\gamma = \alpha \beta$と分割できて列$\alpha, \beta$はそれぞれそれ単体では良い部分列を持たないとする。
このとき$\gamma$中に含まれない記号$c$を使って$\gamma' = c \alpha c \beta$ (あるいは$\alpha c \beta c$)は$\gamma$の$2$倍の数の良い部分列を持つ。
さらに$\gmmma' = \alpha' \beta'$と同様の分割が可能。
同様に$c \alpha \beta c$あるいは$\alpha c c \beta$は$\gamma$よりひとつ多い良い部分列を持つ。
これは高々$4\log N \le 160$個の長さで抑えられて要件を満たす。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
x = []
y = []
k = 1
for c in bin(n + 1)[2 :][1 :]:
    x += [ k ]
    y += [ k ]
    k += 1
    if int(c):
        x = [ k ] + x
        y += [ k ]
        k += 1
print(len(x + y))
print(*(x + y))
```
