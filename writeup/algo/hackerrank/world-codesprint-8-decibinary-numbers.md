---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/world-codesprint-8-decibinary-numbers/
  - /blog/2016/12/20/world-codesprint-8-decibinary-numbers/
date: "2016-12-20T02:33:05+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "dp", "oeis" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/decibinary-numbers" ]
---

# HackerRank World CodeSprint 8: Decibinary Numbers

## problem

整数$d$の$10$進数を$d = d\_{n-1}\cdot 10^{n-1} + \dots + d_2 \cdot 10^2 + d_1 \cdot 10^1 + d_0 \cdot 10^0$としたとき、関数$\mathrm{decibinary}(d) = d\_{n-1}\cdot 2^{n-1} + \dots + d_2 \cdot 2^2 + d_1 \cdot 2^1 + d_0 \cdot 2^0$とする。
自然数の全体を$(\mathrm{decibinary}(n), n)$の辞書順に並べるとき、この順序で$x_i$番目($i \lt q$)の自然数をそれぞれ答えよ。

## solution

DP.
Define $\mathrm{dp}(l, y, d)$ be the number of decibinaries which has length $l$ and be evaluated to integer $y$ and starts with digit $d$.
Let $L = \max_i \mathrm{decibinary}(x_i) \le 285112$, then $O(DL \log L)$.
You should take care to avoid MLE.

## implementation

The OEIS's A007728 was finally useless, but helped me to debug it.

``` c++
// https://oeis.org/A007728
ll a007728(int n) {
    static unordered_map<uint64_t, ll> memo;
    function<ll (int, int)> f = [&](int n, int i) {
        if (n <  0) return 0ll;
        if (n == 0) return 1ll;
        if (i <  0) return 0ll;
        uint64_t key = uint64_t(n) | (uint64_t(i) << 48); // TODO: why is this fast?
        if (memo.count(key)) return memo[key];
        ll acc = 0;
        repeat (j,5) acc += f(n-j*(1<<i), i-1);
        return memo[key] = acc;
    };
    return f(n, n == 0 ? -1 : floor(log2(n)));
}
ll decibinary(int n) { // the number of decibinaries which is evaluated to given n
    static vector<ll> memo;
    while (n >= int(memo.size())) {
        int i = memo.size();
        memo.push_back((i == 0 ? 0 : memo.back()) + (i % 2 == 0 ? a007728(i / 2) : 0));
    }
    return memo[n];
}
```

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    // prepare
    const int max_decimal = 285112+3;
    const int len = ceil(log2(max_decimal))+1;
    auto dp = vectors(len+1, 10, vector<ll>());
    repeat (i,len+1) repeat (d,10) dp[i][d].resize(min(max_decimal, 9*(1<<(i+1)))); // to avoid MLE
    auto sdp = vectors(len+1, max_decimal+1, ll()); // sum of dp
    dp[0][0][0] = 1;
    sdp[0][0] = 1;
    repeat (i,len) {
        repeat (d,10) {
            repeat (x,dp[i][d].size()) if (x-d*(1<<i) >= 0) {
                dp[i+1][d][x] = sdp[i][x-d*(1<<i)];
                sdp[i+1][x] += dp[i+1][d][x];
            }
        }
    }
    auto at = [&](int i, int d, int x) { return x < dp[i][d].size() ? dp[i][d][x] : 0; };

    auto ssdp = vectors(max_decimal+1, ll()); // the number of decibinaries which is evaluated to x
    ssdp[0] = 1;
    repeat (i,len) {
        repeat (x,max_decimal+1) {
            ssdp[x] += sdp[i][x] - at(i,0,x);
        }
    }
    sdp = vectors(0, 0, ll());

    auto sssdp = vectors(max_decimal+1, ll()); // the number of decibinary which is evaluated to y < x
    repeat (x,max_decimal) sssdp[x+1] = sssdp[x] + ssdp[x];
    repeat (x,max_decimal) assert (sssdp[x+1] >= 0);
    assert (ll(1e16) < sssdp.back());
    ssdp = vectors(0, ll());

    function<string (ll)> th = [&](ll i) { // the i-th decibinary
        int x = whole(upper_bound, sssdp, i) - sssdp.begin() - 1;
        ll j = i - sssdp[x];
        string s;
        repeat_reverse (i,len) {
            int d = 0;
            while (at(i+1,d,x) < j+1) {
                j -= at(i+1,d,x);
                d += 1;
                assert (j >= 0);
                assert (d <= 9);
            }
            x -= d*(1<<i);
            assert (x >= 0);
            if (not s.empty() or d != 0) s += (d + '0');
        }
        if (s.empty()) s += '0';
        return s;
    };

    // input/output
    int q; cin >> q;
    while (q --) {
        ll i; cin >> i; -- i;
        cout << th(i) << endl;
    }
    return 0;
}
```
