---
layout: post
redirect_from:
  - /writeup/algo/atcoder/jag2017summer-day3-b/
  - /blog/2017/10/03/jag2017summer-day3-b/
date: "2017-10-03T06:58:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag-summer" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2017summer-day3/tasks/jag2017summer_day3_b" ]
---

# Japan Alumni Group Summer Camp 2017 Day 3: B - Slimming Plan

実装が下手でバグらせた。
$D$日ずつまとめて見ていくところを除算でしていたのが悪かった。
チームメンバーにloopでやればよさそうと言われ修正してAC。

## problem

体重を$S$から$T$以下に減らしたい。
$d \in \mathbb{N}$日目には体重が$w\_{d \bmod D}$減る。
最初に$T$以下になるのは何日目か。

## solution

$D$日ずつまとめて飛ばしていき、最後の付近は$1$日ずつ見る。
$D$日間の途中で大きく減るが最後に戻して$1$周期で見るとあまり減らないケースのため、$D$日間での最小値を持つ必要があることに注意。
上手くやれば$O(D)$、安全に倒して書けば$O(D + T)$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

ll solve(ll s, ll t, ll d, vector<int> const & w) {
    ll delta = 0;
    ll min_delta = 0;
    repeat (i, d) {
        if (s + delta <= t) return i;
        delta += w[i];
        setmin(min_delta, delta);
    }
    if (delta >= 0) return -1;
    ll i = 0;
    ll acc = 0;
    for (; s + acc + min_delta > t; i += d) {
        acc += delta;
    }
    for (; s + acc > t; ++ i) {
        acc += w[i % d];
    }
    return i;
}

int main() {
    int s, t, d; scanf("%d%d%d", &s, &t, &d);
    vector<int> w(d); repeat (i, d) scanf("%d", &w[i]);
    ll result = solve(s, t, d, w);
    printf("%lld\n", result);
    return 0;
}
```
