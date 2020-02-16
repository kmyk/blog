---
layout: post
redirect_from:
  - /blog/2016/07/23/arc-058-d/
date: "2016-07-23T23:10:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "combination" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc058/tasks/arc058_b" ]
---

# AtCoder Regular Contest 058 D - いろはちゃんとマス目 / Iroha and a Grid

## solution

右下から$(B,A)$の点から左上に向かってななめになめる。$O(H+W)$。

領域が長方形$H \times W$であればその経路数${}\_{H+W}C_H$は、前処理$O(N)$を使って$O(1)$で求まる。
しかし今回の領域は長方形でなく、L字型をしている。
これを適切に長方形に分けることを考える。
つまり、領域内の座標の集合$\\{ p_0, \dots, p\_{n-1} \\}$を使って、全体の経路数$\mathrm{ans} = \Sigma\_{i \lt n} (\text{左上から} p_i \text{までの経路数}) \cdot (p_i \text{から右下までの経路数})$としたい。
このような$p_i$に関して、左上から$p_i$あるいは$p_i$から右下への経路中に他の点$p_j$($j \ne i$)が現れてはならない。
これを満たすような$p_i$のとりかたは、右下から$(B,A)$の点から左上に向かってななめに集めてきた$\\{(H-A-1,B), (H-A-2, B+1), \dots \\}$である。
これを計算すればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;

const int mod = 1e9+7;

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
ll choose(ll n, ll r) { // O(n) at first time, otherwise O(1)
    static vector<ll> fact(1,1);
    static vector<ll> ifact(1,1);
    if (fact.size() <= n) {
        int l = fact.size();
        fact.resize( n + 1);
        ifact.resize(n + 1);
        repeat_from (i,l,n+1) {
            fact[i]  = fact[i-1] * i % mod;
            ifact[i] = inv(fact[i], mod);
        }
    }
    r = min(r, n - r);
    return fact[n] * ifact[n-r] % mod * ifact[r] % mod;
}

int main() {
    int h, w, a, b; scanf("%d%d%d%d", &h, &w, &a, &b);
    ll ans = 0;
    a = h - a - 1;
    for (; a >= 0 and b < w; -- a, ++ b) {
        int c = h - a - 1;
        int d = w - b - 1;
        ans += choose(a + b, a) * choose(c + d, d) % mod;
        ans %= mod;
    }
    printf("%lld\n", ans);
    return 0;
}
```
