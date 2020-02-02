---
layout: post
alias: "/blog/2017/07/09/agc-017-b/"
date: "2017-07-09T23:44:36+09:00"
title: "AtCoder Grand Contest 017: B - Moderate Differences"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc017/tasks/agc017_b" ]
---

## solution

増加の回数を$k$、減少の回数を$N - k$としてこの$k$を全探索。$O(N)$。

区間$[l, r]$を関数$X \mapsto \\{ x + \delta \mid x \in X, \delta \in [l, r]\\}$と見る。
この関数は明らかに可換: $[l, r] \circ [l', r'] = [l', r'] \circ [l, r] = [l + l', r + r']$。
また$x, x'$が隣り合っているとき、$x' \in [C, D](\\{ x \\})$または$x' \in [-D, -C](\\{ x \\})$が成り立つことが条件。
よって問題全体は$B \in ({[C, D]}^k \circ {[-D, -C]}^{N-k})(\\{ A \\})$であるような$k$が存在するか否かであると整理される。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    int n; ll a, b, c, d; scanf("%d%lld%lld%lld%lld", &n, &a, &b, &c, &d);
    bool found = false;
    repeat (k, n) {
        ll r1 = d * k;
        ll l1 = c * k;
        ll r2 = - c * (n - 1 - k);
        ll l2 = - d * (n - 1 - k);
        ll r = r1 + r2;
        ll l = l1 + l2;
        if (l <= abs(b - a) and abs(b - a) <= r) {
            found = true;
        }
    }
    printf("%s\n", found ? "YES" : "NO");
    return 0;
}
```
