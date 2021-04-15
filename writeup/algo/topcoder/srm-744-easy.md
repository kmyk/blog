---
redirect_from:
layout: post
date: 2018-12-15T04:00:00+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "matrix" ]
---

# TCO19 Single Round Match 744: Easy - ModularQuadrant

<!-- {% raw %} -->

## 問題概要

$$f(y, x) = \min \{ y, x \} \bmod 3$$ としたとき $$\sum _ {r_1 \le y \le r_2} \sum _ {c_1 \le x \le c_2} f(y, x)$$ を求めよ

## 解法

### 概要

やるだけだけど面倒。
包除原理と行列累乗でやるのが最も楽だと思う。
$$O(\log \max \{ r_2, c_2 \})$$。

### 詳細

包除原理をすればよいので $$r_1 = c_1 = 0$$ と仮定してよい。
対称性から $$r = r_2 \le c = c_2$$ と仮定してよい。

$$r \times r$$ の正方形の領域と $$r \times (c - r)$$ の長方形の領域のふたつに分けてそれぞれ考える。
後者はさらに包除原理をすればよい。
前者は以下の図のような模様の総和を取ることになる。

```
.       .
.      .
.     .
222222
111112
000012
222012
112012
012012...
```

$$2$$ を近くの $$1$$ にずらすようにして考えて $$r^2$$ から差を引いて求めてもよいが、次のようなコードをloop unrollingした結果を行列で表現して行列累乗をするのが最も頭を使わないだろう。

``` c++
ll acc = 0;
for (int i = 0; i < n; ++ i) {
    acc += (i % 3) * (2 * i + 1);
}
```

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
typedef long long ll;
using namespace std;
class ModularQuadrant { public: long long sum(int r1, int r2, int c1, int c2); };

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

ll solve2(ll w, ll z) {
    ll k = w / 3 * 3;
    if (w % 3 == 2) k += 1;
    return k * z;
}

ll solve1(ll y, ll x) {
    matrix<ll, 3, 3> f0 = {{ {{ 1, 0, 0 }}, {{ 0, 1, 2 }}, {{ 0, 0, 1 }} }};
    matrix<ll, 3, 3> f1 = {{ {{ 1, 1, 0 }}, {{ 0, 1, 2 }}, {{ 0, 0, 1 }} }};
    matrix<ll, 3, 3> f2 = {{ {{ 1, 2, 0 }}, {{ 0, 1, 2 }}, {{ 0, 0, 1 }} }};
    ll z = min(y, x);
    auto g = powmat<ll>(f2 * f1 * f0, z / 3);
    if (z % 3 >= 1) g = f0 * g;
    if (z % 3 >= 2) g = f1 * g;
    return (g * array<ll, 3>({{ 0, 1, 1 }}))[0] + solve2(max(y, x), z) - solve2(z, z);
}

long long ModularQuadrant::sum(int r1, int r2, int c1, int c2) {
    return solve1(r2 + 1, c2 + 1) - solve1(r2 + 1, c1) - solve1(r1, c2 + 1) + solve1(r1, c1);
}
```

<!-- {% endraw %} -->
