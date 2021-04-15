---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-711-easy/
  - /blog/2017/03/27/srm-711-easy/
date: "2017-03-27T13:35:17+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "greedy" ]
"target_url": [ "https://community.topcoder.com/stat?c=problem_statement&pm=14558" ]
---

# TopCoder SRM 711 Div1 Easy: ConsecutiveOnes

## problem

整数$N, K$が与えられる。$N \le M$かつ$2$進数展開すると全て$1$な連続する$K$ bitがある、を満たす最小の整数$M$を答えよ。

## solution

貪欲。$O((k + \log n)^2)$ぐらい。

とりあえず全てのbitを立てて(あるいは下位$k$ bitを立てて)、大きい側から貪欲に倒していけばよい。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class ConsecutiveOnes { public: ll get(ll n, int k); };

ll ConsecutiveOnes::get(ll n, int k) {
    ll mask = 0; repeat (i,k) mask = (mask << 1) | 1;
    auto pred = [&](ll m) {
        for (ll s = mask; s > 0; s <<= 1) {
            if ((m & s) == s) {
                return true;
            }
        }
        return false;
    };
    ll m = n | mask;
    for (ll i = 1ll << 52; i; i >>= 1) {
        ll nm = m & (~ i);
        if (n <= nm and pred(nm)) {
            m = nm;
        }
    }
    return m;
}
```
