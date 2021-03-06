---
layout: post
redirect_from:
  - /writeup/algo/codeforces/697-e/
  - /blog/2016/07/15/cf-697-e/
date: "2016-07-15T04:00:29+09:00"
tags: [ "competitive", "writeup", "codeforces", "exponentiation-by-squaring", "wolfram-alpha" ]
"target_url": [ "http://codeforces.com/contest/697/problem/E" ]
---

# Codeforces Round #362 (Div. 2) E. PLEASE

I've got the 3rd place in the Div2 and the rating $+233$.

## problem

$3$つのカップがあり、始めは中央のカップに鍵が入っている。
中央のカップと、端のカップのいずれか(ランダムに選ばれる)を入れ換えることを$n = \Pi\_{i \le k} a_i$回繰り返す。
最終的に中央のカップに鍵が入っている確率を答えよ。

## solution

Exponentiation of matrix. <a href="https://www.wolframalpha.com/input/?i=((1%2F2,1%2F2),(1,0))%5En">Wolfram|Alpha</a> helps you. $O(\log n)$.

Carefully see or do experiment on the Wolfram Alpha's answer, $\frac{(-1)^n + 2^{n-1}}{3 \cdot 2^{n-1}}$ is always reducible by (only) $3$.
So you should only print this.

## implementation

I've written it with python, but it causes TLE.

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;

ll powi(ll x, ll y, ll p) {
    assert (y >= 0);
    x = (x % p + p) % p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll inv(ll x, ll p) {
    assert ((x % p + p) % p != 0);
    return powi(x, p-2, p);
}

const int mod = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    vector<ll> xs(n); repeat (i,n) scanf("%I64d", &xs[i]);
    ll a = -1;
    ll b = 2;
    for (ll x : xs) {
        a = powi(a, x, mod);
        b = powi(b, x, mod);
    }
    ll p = (2 * a + b) % mod * inv(6, mod) % mod;
    ll q = (    3 * b) % mod * inv(6, mod) % mod;
    printf("%I64d/%I64d\n", p, q);
    return 0;
}
```
