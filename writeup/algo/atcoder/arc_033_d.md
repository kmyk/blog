---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_033_d/
  - /writeup/algo/atcoder/arc-033-d/
  - /blog/2017/05/10/arc-033-d/
date: "2017-05-10T21:48:48+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "polynomial-interpolation", "lagrange-interpolation" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc033/tasks/arc033_4" ]
---

# AtCoder Regular Contest 033: D - 見たことのない多項式

多項式補完、ほぼ知らなかった

## solution

Lagrange補完をする。普通にやると$O(N^2 \log \mathrm{mod})$だが、点が$0, 1, \dots, N+1$まで等間隔で与えられることを使えば$O(N \log \mathrm{mod})$。

Lagrange補完について。
目的の(直接参照できない)$n$次多項式$f(x)$に対し、相異なる$n+1$点$x\_0, x\_1, \dots, x\_n$とその点での値$f(x\_0), f(x\_1), \dots, f(x\_n)$が既知であるとする。
このとき$y = f(x)$を次のように計算できる:
$$
    y = f(x) = \sum\_{0 \le j \le n} f(x_j) \frac{g\_j(x)}{g\_j(x\_j)}
$$
ただし:
$$
    g\_j(x') = \prod{0 \le k \le n \land k \ne j} (x' - x\_k)
$$

上を愚直に行うと(今回逆元を取るのは$O(\log \mathrm{mod})$なのでこれを含めて)$O(N^2\log \mathrm{mod})$である。
ここで$n+1$点$x\_0, x\_1, \dots, x\_n$の与えられ方を用いて、前処理$O(N)$を使って$O(1)$で$g\_j(x)$を求める。
これは先に
$$
    g\_x = \prod{0 \le k \le n} (x - x\_k)
$$
を計算しておいて$k = j$のときの$(x - x\_j)$の逆元を掛ける、また$n!$を計算しておいて繋ぎ合わせることで可能。


## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

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
ll inv(ll x, ll p) { // p must be a prime, O(log p)
    assert ((x % p + p) % p != 0);
    return powmod(x, p-2, p);
}
constexpr int mod = 1e9+7;

int solve(int n, vector<int> const & f, int x) {
    if (0 <= x and x < n+1) {
        return f[x];
    }
    // Lagrange interpolation with O(N \log mod)
    ll a = 1;
    repeat (i,n+1) {
        a = a * (x - i +(ll) mod) % mod;
    }
    vector<int> b(n+2);
    b[0] = 1;
    repeat (i,n+1) {
        b[i+1] = b[i] *(ll) (i+1) % mod;
    }
    ll y = 0;
    repeat (i,n+1) {
        ll ai = a * inv((x - i +(ll) mod) % mod, mod) % mod;
        ll bi = inv(b[i] *(ll) b[n-i] % mod, mod);
        if ((n-i) % 2 == 1) bi = mod - bi;
        y += f[i] * ai % mod * bi % mod;
    }
    y %= mod;
    return y;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n+1); repeat (i,n+1) scanf("%d", &a[i]);
    int t; scanf("%d", &t);
    // solve
    int at = solve(n, a, t);
    // output
    printf("%d\n", at);
    return 0;
}
```
