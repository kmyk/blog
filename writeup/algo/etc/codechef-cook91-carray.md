---
layout: post
alias: "/blog/2018/03/31/codechef-cook91-carray/"
title: "CodeChef February Cook-Off 2018: Chef and Line"
date: "2018-03-31T02:12:58+09:00"
tags: [ "competitive", "writeup", "codechef", "greedy" ]
"target_url": [ "https://www.codechef.com/COOK91/problems/CARRAY" ]
---

## problem

非負整数列$A : N \to \mathbb{N}$が与えられる。
その部分列$B$であって、適当に並び変えて$B\_{i + 1} \ge kB\_i + b$ for all $i$であるようにできるもののうち、最長のものの長さを答えよ。

## solution

$B$の条件から始めに$A$をsortしてよい。
すると貪欲に最も小さいものを選べばよいだけになる。
$O(N \log N)$。

## implementation

なんでDPしたんだったっけ？ 考察不足

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch_max(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    ++ r;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? l : r) = m;
    }
    return l;
}

template <typename Monoid>
struct binary_indexed_tree { // on monoid
    typedef typename Monoid::underlying_type underlying_type;
    vector<underlying_type> data;
    Monoid mon;
    binary_indexed_tree(size_t n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        data.resize(n, mon.unit());
    }
    void point_append(size_t i, underlying_type z) { // data[i] += z
        for (size_t j = i + 1; j <= data.size(); j += j & -j) data[j - 1] = mon.append(data[j - 1], z);
    }
    underlying_type initial_range_concat(size_t i) { // sum [0, i)
        underlying_type acc = mon.unit();
        for (size_t j = i; 0 < j; j -= j & -j) acc = mon.append(data[j - 1], acc);
        return acc;
    }
};
struct max_monoid {
    typedef int underlying_type;
    int unit() const { return INT_MIN; }
    int append(int a, int b) const { return max(a, b); }
};


int solve(int n, ll a, ll b, vector<ll> x) {
    sort(ALL(x));
    binary_indexed_tree<max_monoid> dp(n + 1);
    dp.point_append(0, 0);
    REP (i, n) {
        int j = binsearch_max(-1, i - 1, [&](int j) {
            return a * x[j] + b <= x[i];
        });
        dp.point_append(i + 1, dp.initial_range_concat(j + 2) + 1);
    }
    return dp.initial_range_concat(n + 1);
}

int main() {
    int t; cin >> t;
    while (t --) {
        int n; ll a, b; cin >> n >> a >> b;
        vector<ll> x(n); REP (i, n) cin >> x[i];
        int result = solve(n, a, b, x);
        cout << result << endl;
    }
    return 0;
}
```
