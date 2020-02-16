---
layout: post
redirect_from:
  - /blog/2017/07/23/agc-018-a/
date: "2017-07-23T23:16:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "gcd", "euclidean-algorithm" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc018/tasks/agc018_a" ]
---

# AtCoder Grand Contest 018: A - Getting Difference

B解けてA解けない人が見られた。

## solution

$\max A\_i \lt K$なら自明に不可能。
$d = \operator{gcd} \\{ A\_1, A\_2, \dots, A\_N \\}$として$K \not\equiv 0 \pmod{d}$でも不可能。
それ以外なら可能。
$O(N \log \max A\_i)$。

$K \le \max A\_i$かつ$K \equiv 0 \pmod{d}$なら可能であることを示す。
$K, A\_1, A\_2, \dots, A\_N$を全て$d$で割ってとりなおすことで$d = 1$と仮定してかまわない。
このとき$K$でなく$1$が作れることを示せば十分。$\| \max A\_i - 1 \| = \max A\_i - 1, \; \| (\max A\_i - 1) - 1 \| = \max A\_i - 2, \; \dots$と上から$K$まで作ればよいため。
$d = 1$なら$1$が作れるのはEuclidの互除法を思い出せば示せる。
互除法と同じ手続きがこの数列の上で可能であるのを見ればよい。

ボールは減らないという点の誤読にも注意。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

ll gcd(ll a, ll b) { while (a) { b %= a; swap(a, b); } return b; }

bool solve(vector<ll> & a, ll k) {
    assert (not a.empty());
    assert (k != 0);
    whole(sort, a);
    a.erase(whole(unique, a), a.end());
    if (a.back() < k) return false;
    ll gcd_a = a[0]; for (ll a_i : a) gcd_a = gcd(gcd_a, a_i);
    if (k % gcd_a != 0) return false;
    return true;
}

int main() {
    int n; ll k; scanf("%d%lld", &n, &k);
    vector<ll> a(n); repeat (i, n) scanf("%lld", &a[i]);
    bool result = solve(a, k);
    printf("%s\n", result ? "POSSIBLE" : "IMPOSSIBLE");
    return 0;
}
```
