---
layout: post
alias: "/blog/2017/03/27/srm-711-med/"
date: "2017-03-27T13:35:20+09:00"
title: "TopCoder SRM 711 Div1 Medium: OrderedProduct"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "inclusion-exclusion-principle" ]
"target_url": [ "https://community.topcoder.com/stat?c=problem_statement&pm=14550" ]
---

Div1 $40$位を取ってレート爆上げした。嬉しい。

## problem

巨大な整数$X$が素因数分解された形で与えられる。$1$を含まない整数列で総乗が$X$になるものの数を答えよ。

## solution

長さを固定してそれぞれ計算する。包除原理を陽あるいは陰に使う。$\max a_i \le N$としてまとめて書いて$O(N^4 \log N)$。適切にやれば$O(N^3)$。

列の長さを$l$として、係数$a_i$らを総乗が$X$になるように分配することを考える。
$1$を要素として含むことを許容すれば$k = \prod_i {}\_lH\_{a_i}$個の異なる列が作れる。ただし${}\_nH_r$は重複組み合わせ。
$1$を要素として含むことは禁止されているので$\mathrm{dp}\_l = k - \sum\_{i \lt l} \mathrm{dp}\_i$とする。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class OrderedProduct { public: int count(vector<int> a); };

constexpr int mod = 1e9+7;
int powmod(int x, int y) { // O(log y)
    assert (0 <= x and x < mod);
    assert (0 <= y);
    int z = 1;
    for (int i = 1; i <= y; i <<= 1) {
        if (y & i) z = z *(ll) x % mod;
        x = x *(ll) x % mod;
    }
    return z;
}
int inv(int x) { // p must be a prime, O(log p)
    return powmod(x, mod-2);
}
int fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
int choose(int n, int r) { // O(n) at first time, otherwise O(\log n)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact(n) *(ll) inv(fact(n-r)) % mod *(ll) inv(fact(r)) % mod;
}
int multichoose(int n, int r) {
    if (n == 0 and r == 0) return 1;
    return choose(n+r-1, r);
}

int OrderedProduct::count(vector<int> a) {
    int n = a.size();
    int sum_a = accumulate(a.begin(), a.end(), 0);
    vector<int> dp(sum_a+1);
    repeat (l,sum_a+1) {
        ll cnt = 1;
        repeat (i,n) {
            cnt = cnt * multichoose(l, a[i]) % mod;
        }
        repeat (l1,l) {
            cnt += - dp[l1] *(ll) choose(l, l1) % mod + mod;
        }
        dp[l] = cnt % mod;
    }
    return accumulate(dp.begin(), dp.end(), 0ll) % mod;
}
```
