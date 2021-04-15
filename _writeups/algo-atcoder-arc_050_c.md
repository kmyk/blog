---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_050_c/
  - /writeup/algo/atcoder/arc-050-c/
  - /blog/2016/04/04/arc-050-c/
date: 2016-04-04T17:37:39+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "math" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc050/tasks/arc050_c" ]
---

# AtCoder Regular Contest 050 C - LCM 111

## 解法

数学。

$\rm{ones}(n) = \overbrace{111\dots 1}^{n \; \text{times}}$とする。
lcmを求めるので、まずは$\rm{lcm}(\rm{ones}(a), \rm{ones}(b)) = \rm{ones}(a) \cdot \rm{ones}(b) / \rm{gcd}(\rm{ones}(a), \rm{ones}(b))$。
$a \le b$として、$\rm{gcd}(\rm{ones}(a), \rm{ones}(b)) = \rm{gcd}(\rm{ones}(b) \bmod \rm{ones}(a), \rm{ones}(a))$であるが、$\rm{ones}(b) \bmod \rm{ones}(a) = \rm{ones}(b \bmod a)$であるので、$\rm{gcd}(\rm{ones}(a), \rm{ones}(b)) = \rm{ones}(\rm{gcd}(a,b))$となる。
また、$b \bmod d = 0$のとき、$\rm{ones}(b) / \rm{ones}(d)$は、$\underbrace{\overbrace{00 \dots 0}^{\frac{b}{d}-1 \; \text{times}}1\overbrace{00 \dots 0}^{\frac{b}{d}-1 \; \text{times}}1\dots \overbrace{00 \dots 0}^{\frac{b}{d}-1 \; \text{times}}1}\_{d \; \text{times}}$と$10$進数表記される整数である。

これらは、行列累乗法で高速に計算できる。

ここで用いた$\rm{ones}(-)$の性質は、
$\overbrace{111 \dots 1}^{b \; \text{times}} = \overbrace{111 \dots 1}^{a \; \text{times}}\overbrace{111 \dots 1}^{a \; \text{times}}\dots \overbrace{111 \dots 1}^{a \; \text{times}}\overbrace{111 \dots 1}^{c \; \text{times}}$ ($c \lt a$)とすると、
$\overbrace{111 \dots 1}^{b \; \text{times}} = (\overbrace{111 \dots 1}^{a \; \text{times}}) \times ( \overbrace{00 \dots 0}^{a-1 \; \text{times}}1\overbrace{00 \dots 0}^{a-1 \; \text{times}}1\dots \overbrace{00 \dots 0}^{a-1 \; \text{times}}1 \overbrace{000 \dots 0}^{c \; \text{times}}) + \overbrace{111 \dots 1}^{c \; \text{times}}$となることから確認できる。
$c = b \bmod a$である。

## 実装

boostの行列なりを使いたかったが、mod取るのが面倒そうなので自前。
ちょっと汚くなってしまった。

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll gcd(ll a, ll b) { if (b < a) swap(a,b); while (a) { ll c = a; a = b % c; b = c; } return b; }
ll lcm(ll a, ll b) { return (a * b) / gcd(a,b); }
ll powi(ll x, ll y, ll p) { x = (x % p + p) % p; ll z = 1; for (ll i = 1; i <= y; i <<= 1) { if (y & i) z = z * x % p; x = x * x % p; } return z; }
ll inv(ll x, ll p) { assert ((x % p + p) % p != 0); return powi(x, p-2, p); }

ll a, b, m; // global

vector<vector<ll> > operator * (vector<vector<ll> > const & p, vector<vector<ll> > const & q) { int n = p.size(); vector<vector<ll> > r(n, vector<ll>(n)); repeat (y,n) { repeat (z,n) { repeat (x,n) { r[y][x] += p[y][z] * q[z][x] % m; r[y][x] %= m; } } } return r; }
vector<ll> operator * (vector<vector<ll> > const & p, vector<ll> const & q) { int n = p.size(); vector<ll> r(n); repeat (y,n) { repeat (z,n) { r[y] += p[y][z] * q[z] % m; r[y] %= m; } } return r; }
vector<vector<ll> > unit_matrix(int n) { vector<vector<ll> > e(n, vector<ll>(n)); repeat (i,n) e[i][i] = 1; return e; }
vector<vector<ll> > mul (vector<vector<ll> > const & p, vector<vector<ll> > const & q) { return p * q; }
template <typename T, typename F> T powt(T x, ll y, T unit, F f) { T z = unit; for (ll i = 1; i <= y; i <<= 1) { if (y & i) z = f(z, x); x = f(x, x); } return z; }

int main() {
    cin >> a >> b >> m;
    ll d = gcd(a, b);
    vector<vector<ll> > f(2, vector<ll>(2));
    vector<vector<ll> > g(2, vector<ll>(2));
    vector<ll> e(2);
    f[0][0] = 10; f[0][1] = 1;
    f[1][0] =  0; f[1][1] = 1;
    g[0][0] = powi(10,d,m); g[0][1] = 1;
    g[1][0] =            0; g[1][1] = 1;
    e[0] = 0;
    e[1] = 1;
    a = (powt(f,   a, unit_matrix(2), &mul) * e)[0];
    b = (powt(g, b/d, unit_matrix(2), &mul) * e)[0];
    cout << a * b % m << endl;
    return 0;
}
```
