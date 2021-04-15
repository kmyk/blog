---
layout: post
redirect_from:
  - /writeup/algo/atcoder/codefestival-2016-grand-final-g/
  - /blog/2018/01/04/codefestival-2016-grand-final-g/
date: "2018-01-04T16:09:24+09:00"
tags: [ "competitive", "writeup", "atcodr", "codefestival", "lie", "random", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-exhibition-final/tasks/cf16_exhibition_final_g" ]
---

# CODE FESTIVAL 2016 Grand Final: G - FESTIVAL

## solution

数列$a$に対し、文字$F$を$a\_0$個並べ後ろに文字$E$を$a\_1$個並べ$\dots$のようにして文字列$s = F^{a\_0}E^{a\_1}S^{a\_2}T^{a\_3}I^{a\_4}V^{a\_5}A^{a\_6}L^{a\_7}F^{a\_8}E^{a\_9}S^{a\_{10}}\dots$を構成することを考える。
この数列$a$を乱択で生成する。
適当に$i$を選び$a\_i$を$1$増やして$K$を越えないならば増やすことを繰り返す。
まったく自由に$i$を選ぶとだめで、$i = 8p + q$と書いたときの対$(p, - q)$の小さい順に選ばれやすくするとよい。
計算量は知らず。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <random>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <typename T, typename Container>
T count_festival(Container const & a) {
    array<T, 8> dp = {};
    repeat (i, a.size()) {
        if (i % 8 == 0) {
            dp[i % 8] += a[i];
        } else {
            dp[i % 8] += dp[i % 8 - 1] * a[i];
        }
    }
    repeat_from (i, 1, 8) {
        dp[i] += dp[i - 1];
    }
    return dp[7];
}
string solve(ll k) {
    array<int, 80> a = {};
    auto get_length = [&]() {
        ll cnt = count_festival<ll>(a);
        assert (cnt <= k);
        return accumulate(whole(a), 0) + (k - cnt) + 7;
    };
    default_random_engine gen;
    for (int iteration = 0; get_length() > 5000; ++ iteration) {
        int limit = iteration < 5000 ? 8 : min<int>(a.size(), 8 + iteration / 100);
        int base = limit / 8 * 8;
        int i = uniform_int_distribution<int>(0, limit - 1)(gen);
        if (base <= i) {
            i = base + 8 - (i - base) - 1;
        }
        a[i] += 1;
        if (count_festival<double>(a) > k or count_festival<ll>(a) > k) {
            a[i] -= 1;
        }
    }
    string s;
    repeat (i, a.size()) {
        s += string(a[i], "FESTIVAL"[i % 8]);
    }
    s += string(k - count_festival<ll>(a), 'F');
    s += "ESTIVAL";
    return s;
}
int main() {
    ll k; cin >> k;
    string s = solve(k);
    cout << s << endl;
    return 0;
}
```
