---
layout: post
alias: "/blog/2017/10/22/kupc-2017-j/"
date: "2017-10-22T13:33:34+09:00"
title: "Kyoto University Programming Contest 2017: J - Paint Red and Make Graph"
tags: [ "competitive", "writeup", "kupc", "atcoder", "matrix", "tree", "bipartite-graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_j" ]
---

後から解いた。本番は間に合わずでほとんど見てない。
二部グラフなら行列の形が綺麗ということらしい。

## solution

行列木定理。行列の形に合わせて掃き出し法。$O(W^2(H+W))$。

$H \times W$の盤面に対し、行と列に対応する$H + W$個の頂点と盤面のマス目に対応する高々$HW$個の辺を持つグラフを作る。
これは$(H, W)$な二部グラフ。
その隣接行列は$H \times W$行列$A$を使って
$$ \left( \begin{matrix}
    O & A \\\\
    A^\top & O \\\\
\end{matrix} \right) $$。
Laplacian行列は
$$ \left( \begin{array}{ccc|ccc}
    d\_1 &        &      &          &        &          \\\\
         & \ddots &      &          & A      &          \\\\
         &        & d\_H &          &        &          \\\\ \hline
         &        &      & d\_{H+1} &        &          \\\\
         & A^\top &      &          & \ddots &          \\\\
         &        &      &          &        & d\_{H+W} \\\\
\end{array} \right) $$のようになる。
余因子を求めるのはほとんど行列式を求めればよい。
掃き出し法をする。
上の$H$行についてはその下の$W$行に対し行基本変形が必要でそれぞれ$1 + W$要素の操作、この部分で$O(HW^2)$。
下の$W$行についてはその行の正規化と残る$H + W - 1$行について行基本変形だが自身より右だけ見ればよいのでそれぞれ$O(W)$、この部分は$O(W^2(H+W))$。
よって全体で$O(W^2(H+W))$。




## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (0 <= x and x < p);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll modinv(ll x, ll p) { // p must be a prime, O(log p)
    assert (x % p != 0);
    return powmod(x, p - 2, p);
}

constexpr int mod = 1e9+7;
int solve(int h, int w, vector<string> const & f) {
    { // check the possibility
        vector<bool> used(h + w);
        function<void (int)> go = [&](int z) {
            used[z] = true;
            if (z < h) {
                repeat (x, w) {
                    if (f[z][x] == '.' and not used[h + x]) {
                        go(h + x);
                    }
                }
            } else {
                repeat (y, h) {
                    if (f[y][z - h] == '.' and not used[y]) {
                        go(y);
                    }
                }
            }
        };
        go(0);
        if (count(whole(used), false)) return -1;
    }
    // make a sparse matrix
    vector<int> a(h);
    vector<vector<int> > b = vectors(h, w - 1, int());
    vector<vector<int> > c = vectors(w - 1, h, int());
    vector<vector<int> > d = vectors(w, w - 1, int());
    int e = 0;
    repeat (y, h) {
        repeat (x, w - 1) {
            if (f[y][x] == '.') {
                a[y] += 1;
                b[y][x] -= 1;
                c[x][y] -= 1;
                d[x][x] += 1;
            }
        }
        if (f[y][w - 1] == '.') {
            a[y] += 1;
            e += 1;
        }
    }
    // eliminate
    repeat (z, h) {
        repeat (y, w - 1) {
            if (c[y][z]) {
                if (a[z] == 0) return 0;
                ll k = c[y][z] * modinv(a[z], mod) % mod;
                c[y][z] = 0;
                repeat (x, w - 1) {
                    d[y][x] -= k * b[z][x] % mod;
                    if (d[y][x] < 0) d[y][x] += mod;
                }
            }
        }
    }
    repeat (z, w - 1) {
        repeat (y, h) {
            if (d[z][z] == 0) return 0;
            ll k = b[y][z] * modinv(d[z][z], mod) % mod;
            repeat_from (x, z, w - 1) {
                b[y][x] -= k * d[z][x] % mod;
                if (b[y][x] < 0) b[y][x] += mod;
            }
        }
        repeat (y, w - 1) if (y != z) {
            if (d[z][z] == 0) return 0;
            ll k = d[y][z] * modinv(d[z][z], mod) % mod;
            repeat_from (x, z, w - 1) {
                d[y][x] -= k * d[z][x] % mod;
                if (d[y][x] < 0) d[y][x] += mod;
            }
        }
    }
    // prod
    ll result = 1;
    repeat (z, h) {
        result *= a[z];
        result %= mod;
    }
    repeat (z, w - 1) {
        result *= d[z][z];
        result %= mod;
    }
    return result;
}

int main() {
    // input
    int h, w; cin >> h >> w;
    vector<string> f(h); repeat (y, h) cin >> f[y];
    // solve
    int result = solve(h, w, f);
    // output
    if (result == -1) {
        printf("-1\n");
    } else {
        printf("%d %d\n", h + w - 1, result);
    }
    return 0;
}
```
