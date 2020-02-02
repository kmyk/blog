---
layout: post
alias: "/blog/2016/05/31/arc-015-d/"
title: "AtCoder Regular Contest 015 D - きんいろクッキー"
date: 2016-05-31T23:44:51+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "probability", "expected-value" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc015/tasks/arc015_4" ]
---

確率/期待値ゲーで、誤差の許容が広い、結果の値がとても大きい、などの怪しげな点が多いので身構えていた。しかし特に難しい点はなかった。

## solution

現在の倍率を更新しながら時間をなめる。$O(N + T)$。

時刻$t$での倍率$x_t$と、倍率の変化率$(\delta x)\_t$を持って、時刻$t = 0$から$t = T-1$までなめる。
$x_0 = 1$であり、$(\delta x)\_0 = (1 - p) + p \cdot \Sigma_i q_i \cdot x_i$から始めて、
$x\_{t+1} = x_t \cdot (\delta x)\_t$, $(\delta x)\_{t+1} = (\delta x)\_t + \Sigma\_{i \operatorname{if} t_i = t+1} (1 - q_i \cdot x_i)$と更新していく。

倍率の変化率$(\delta x)\_t$は広義単調に減少し$1$に収束する。
これは、倍率$x_t$の原因となる時刻の区間を広げているからで、また、効果持続期間$t_i$を越えると倍率は増加しなくなるためである。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

struct cookie_t { double q; int x, t; };
bool operator < (cookie_t a, cookie_t b) { return a.t < b.t; } // strict weak ordering
int main() {
    int t, n; double p; cin >> t >> n >> p;
    vector<cookie_t> cs(n); repeat (i,n) cin >> cs[i].q >> cs[i].x >> cs[i].t;
    sort(cs.begin(), cs.end());
    long double dx = (1 - p) * 1;
    for (cookie_t c : cs) dx += p * c.q * c.x;
    long double x = 1;
    long double ans = 0;
    auto it = cs.begin();
    repeat (i,t) {
        ans += x;
        while (it != cs.end() and it->t == i) {
            dx -= p * it->q * it->x;
            dx += p * it->q * 1;
            ++ it;
        }
        x *= dx;
    }
    printf("%.7Lf\n", ans);
    return 0;
}
```
