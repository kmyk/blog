---
layout: post
alias: "/blog/2016/05/01/hackerrank-world-codesprint-april-daniel-triplets/"
title: "HackerRank World Codesprint April: Lovely Triplets"
date: 2016-05-01T12:21:14+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "graph", "graphviz" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-april/challenges/daniel-triplets" ]
---

I misread the problem statement and be taken much time.

## 問題

整数$P,Q$が固定される。

単純グラフ$G$の頂点の3つ組$(u, v, w) \in V \times V \times V$が良い3つ組であるとは、$d(u,v) = d(v,w) = d(w,u) = Q$が成り立つ、とする。
ここで$d$は、$2$頂点間の最短距離$d : V \times V \to \mathbb{N}$である。

単純グラフが良いグラフであるとは、その頂点$V$の3つ組で、良い3つ組がちょうど$P$個存在する、とする。
必ずしも連結でなくてもよい。

良いグラフ$G$で、頂点数$\|V\| \le 100$、変数$\|E\| \le 100$であるようなものを構成せよ。

## 解法

Make a graph with $O(\sqrt{P})$ vertices.

This is a graph for $P = 60 = 3 \cdot 4 \cdot 5, Q = 9$, with the $\|V\| = 24 = 4 \cdot 3 + 3 + 4 + 5$.
To decide how to factorize, it may require some search.

[![](/blog/2016/05/01/hackerrank-world-codesprint-april-daniel-triplets/a.svg)](/blog/2016/05/01/hackerrank-world-codesprint-april-daniel-triplets/a.dot)

If the $Q$ is even, then the center triangle can be one vertex.
However you must notice that the graph becomes a star graph when $Q = 2$, like below (the $P = 35 = {}\_7C_3$):

[![](/blog/2016/05/01/hackerrank-world-codesprint-april-daniel-triplets/b.svg)](/blog/2016/05/01/hackerrank-world-codesprint-april-daniel-triplets/b.dot)

## 実装

$O(N^2)$の探索をいい感じにごまかした。
c++だったら不要だっただろう。

``` python
#!/usr/bin/env python3
def choose(n, r):
    return n * (n-1) * (n-2) // (r * (r-1) * (r-2))
def product(xs):
    y = 1
    for x in xs:
        y *= x
    return y
def generate_primes(n):
    p = [True] * (n + 1)
    p[0] = False
    p[1] = False
    for i in range(n+1):
        if p[i]:
            yield i
            for j in range(2*i,n+1,i):
                p[j] = False
primes = list(generate_primes(5000))
def factorize(n):
    qs = []
    for p in primes:
        if p*p > n:
            break
        while n % p == 0:
            qs.append(p)
            n //= p
    if n != 1:
        qs.append(n)
    return qs
def core_size(q):
    return ((q - 1) // 2) * 3
def select_factors(p, q, width, memo):
    if p in memo:
        return memo[p]
    qs = [p, 1, 1]
    qv = core_size(q) + sum(qs)
    for i in range(min(width, p)):
        ps = [1, 1, 1]
        for r in factorize(p - i):
            ps[ps.index(min(ps))] *= r
        pv = core_size(q) + sum(ps)
        if i:
            nps, npv = select_factors(p - product(ps), q, width=width, memo=memo)
            pv += npv
        if pv < qv:
            qs = ps
            qv = pv
    memo[p] = (tuple(qs), qv)
    return memo[p]
def make_core(v, e, q):
    if q % 2 == 1:
        xs, v = [v, v+1, v+2], v+3
        for i in range(3):
            e.append((xs[i], xs[(i+1)%3]))
    else:
        xs, v = [v, v, v], v+1
    for i in range(3):
        for j in range(q//2 - 1):
            e.append((xs[i], v))
            xs[i] = v
            v += 1
    return xs, v
def make_triplets(v, e, q, ps):
    xs, v = make_core(v, e, q)
    for i in range(3):
        for _ in range(ps[i]):
            e.append((xs[i], v))
            v += 1
    return v
def make_coalesced_core(v, e, l):
    for i in range(l):
        e.append((v, v + i+1))
    v += l+1
    return v
p, q = map(int,input().split())
v = 0
e = []
if q == 2:
    while p:
        l = 3
        while choose(l+1,3) <= p:
            l += 1
        p -= choose(l,3)
        v = make_coalesced_core(v, e, l)
else:
    while p:
        ps, _ = select_factors(p, q, width=500, memo={})
        v = make_triplets(v, e, q, ps)
        p -= product(ps)
print(v, len(e))
assert v <= 100
for a, b in e:
    print(a+1, b+1)
```
