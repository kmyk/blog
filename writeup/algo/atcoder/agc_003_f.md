---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-003-f/
  - /blog/2018/03/15/agc-003-f/
date: "2018-03-15T03:29:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "matrix", "exponentiation-by-squaring" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc003/tasks/agc003_f" ]
---

# AtCoder Grand Contest 003: F - Fraction of Fractal

<!-- {% raw %} -->

## solution

行列累乗。$O(HW + \log K)$。

制約より与えられる黒マスは連結。
横に並べたとき上下左右に繋がるなら帰納的に答えは$1$。
まったく繋がっていないなら黒マスの数$a$に対し答えは$a^{K-1}$、ただし$K \ne 0$。
そうでないと仮定する。
$90$度回転をして、左右にのみ繋がってると仮定してよい。

以下の$4$変数を用意する。

-   $a$ 黒マスの数
-   $b$ 横方向に隣接する黒マスの対の数
-   $c$ 左端と右端が共に黒マスであるような行の数。
-   $d$ 連結成分の数

これらの間は線形の連立漸化式が立つ。よって$O(\log K)$。
まったく繋がっていない場合は場合分けが必須であることに注意。

## memo

-   見るからに行列累乗だし実際当たってた
-   誤読。連結性の見落とし
    -   誤読したままでも方針は変わらない気がするがどうなのでしょうか
-   きっちり詰める部分つらかった 集中力がない

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

ll powmod(ll x, ll y, ll m) {
    assert (0 <= x and x < m);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % m;
        x = x * x % m;
    }
    return z;
}
constexpr int mod = 1e9 + 7;

template <typename T, size_t H, size_t W>
using matrix = array<array<T, W>, H>;
template <typename T, size_t A, size_t B, size_t C>
matrix<T, A, C> operator * (matrix<T, A, B> const & a, matrix<T, B, C> const & b) {
    matrix<T, A, C> c = {};
    REP (y, A) {
        REP (z, B) {
            REP (x, C) {
                (c[y][x] += a[y][z] *(ll) b[z][x] % mod) %= mod;
            }
        }
    }
    return c;
}
template <typename T, size_t H, size_t W>
array<T, H> operator * (matrix<T, H, W> const & a, array<T, W> const & b) {
    array<T, H> c = {};
    REP (y, H) {
        REP (z, W) {
            (c[y] += a[y][z] *(ll) b[z] % mod) %= mod;
        }
    }
    return c;
}
template <typename T, size_t N>
matrix<T, N, N> matrix_unit() { matrix<T, N, N> a = {}; REP (i, N) a[i][i] = 1; return a; }
template <typename T, size_t N>
matrix<T, N, N> matrix_pow(matrix<T, N, N> x, ll k) {
    matrix<T, N, N> y = matrix_unit<T, N>();
    for (ll i = 1; i <= k; i <<= 1) {
        if (k & i) y = y * x;
        x = x * x;
    }
    return y;
}

int solve1(int h, int w, ll k, vector<string> const & s) {  // s is horizontally connected
    int a = 0;  // number of cells
    int b = 0;  // number of horizontally adjacent pairs of cells
    int c = 0;  // number of horizontally loops
    REP (y, h) REP (x, w) if (s[y][x] == '#') {
        a += 1;
        b += (x + 1 <  w and s[y][x + 1] == '#');
        c += (x + 1 == w and s[y][0] == '#');
    }
    matrix<ll, 4, 4> f = {{
        {{ a,  0, 0, 0 }},
        {{ 0,  a, b, 0 }},
        {{ 0,  0, c, 0 }},
        {{ 1, -1, 0, 0 }},
    }};
    array<ll, 4> x = {{ 1, 0, 1, 1 }};
    array<ll, 4> y = matrix_pow(f, k) * x;
    ll d = y[3];  // number of components
    return (d + mod) % mod;
}

int solve(int h, int w, ll k, vector<string> const & s) {
    bool hr = false;
    REP (y, h) {
        if (s[y][0] == '#' and s[y][w - 1] == '#') {
            hr = true;
        }
    }
    bool vr = false;
    REP (x, w) {
        if (s[0][x] == '#' and s[h - 1][x] == '#') {
            vr = true;
        }
    }
    if (hr and vr) {
        return 1;  // since s is connected
    } else if (hr) {
        return solve1(h, w, k, s);
    } else if (vr) {
        vector<string> t(w, string(h, '\0'));
        REP (x, w) {
            REP (y, h) {
                t[x][y] = s[y][x];
            }
        }
        return solve1(w, h, k, t);
    } else {
        int a = 0;
        REP (y, h) {
            a += count(ALL(s[y]), '#');
        }
        return k == 0 ? 1 : powmod(a, k - 1, mod);
    }
}

int main() {
    int h, w; ll k; cin >> h >> w >> k;
    vector<string> s(h);
    REP (y, h) cin >> s[y];
    int result = solve(h, w, k, s);
    assert (0 <= result and result < mod);
    cout << result << endl;
    return 0;
}
```

<!-- {% endraw %} -->
