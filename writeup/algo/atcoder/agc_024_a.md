---
layout: post
date: 2018-09-29T00:00:44+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "matrix" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc024/tasks/agc024_a" ]
redirect_from:
  - /writeup/algo/atcoder/agc-024-a/
---

# AtCoder Grand Contest 024: A - Fairness

<!-- {% raw %} -->

## 解法

### 概要

行列累乗やるだけ $O(\log K)$

## メモ

想定は$O(1)$だった。思考停止よくないね

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

template <typename T, size_t H, size_t W>
using matrix = array<array<T, W>, H>;
template <typename T, size_t A, size_t B, size_t C>
matrix<T, A, C> operator * (matrix<T, A, B> const & a, matrix<T, B, C> const & b) {
    matrix<T, A, C> c = {};
    REP (y, A) REP (z, B) REP (x, C) c[y][x] += a[y][z] * b[z][x];
    return c;
}
template <typename T, size_t H, size_t W>
array<T, H> operator * (matrix<T, H, W> const & a, array<T, W> const & b) {
    array<T, H> c = {};
    REP (y, H) REP (z, W) c[y] += a[y][z] * b[z];
    return c;
}
template <typename T, size_t N>
matrix<T, N, N> unit_matrix() {
    matrix<T, N, N> a = {};
    REP (i, N) a[i][i] = 1;
    return a;
}
template <typename T, size_t N>
matrix<T, N, N> powmat(matrix<T, N, N> x, ll k) {
    matrix<T, N, N> y = unit_matrix<T, N>();
    for (; k; k >>= 1) {
        if (k & 1) y = y * x;
        x = x * x;
    }
    return y;
}

template <typename T>
T solve1(int a, int b, int c, ll k) {
    matrix<T, 3, 3> f = {{
        {{ 0, 1, 1 }},
        {{ 1, 0, 1 }},
        {{ 1, 1, 0 }},
    }};
    array<T, 3> x = {{ (T)a, (T)b, (T)c }};
    array<T, 3> y = powmat(f, k) * x;
    return y[0] - y[1];
}
ll solve(int a, int b, int c, ll k) {
    auto x = solve1<long double>(a, b, c, k);
    if (abs(x) > 1e18 * 1.1) return LLONG_MAX;
    auto y = solve1<ll>(a, b, c, k);
    if (abs(y) > 1e18) return LLONG_MAX;
    return y;
}

int main() {
    int a, b, c; ll k; cin >> a >> b >> c >> k;
    ll ans = solve(a, b, c, k);
    if (ans == LLONG_MAX) {
        cout << "Unfair" << endl;
    } else {
        cout << ans << endl;
    }
    return 0;
}
```

<!-- {% endraw %} -->
