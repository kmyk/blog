---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/worldcodesprint-colorful-ornaments/
  - /blog/2016/01/31/hackerrank-worldcodesprint-colorful-ornaments/
date: 2016-01-31T01:43:27+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
---

# HackerRank World Codesprint: Alien Flowers

## [Alien Flowers](https://www.hackerrank.com/contests/worldcodesprint/challenges/colorful-ornaments)

### 問題

赤色と青色の玉を一列に並べる。
このとき、赤赤、赤青、青青、青赤、という並びの数がそれぞれ$A,B,C,D$となるような並べ方はいくつあるか。$10^9+7$で割った余りを答えよ。

### 解説

組合せの数${}\_nC_r$を計算する問題に帰着する。

並びは$RRR\dots RBBB\dots BRRR\dots RBBB\dots B\dots$となる。
これは$RRR\dots R, BBB\dots B, RRR\dots R, BBB\dots B, \dots$というグループに分けることができる。このグループの数もそれぞれの色の玉の数も固定できるので、グループへの玉の分配の方法を計算すればよい。

使う玉の個数は$1+A+B+C+D$である。
列が赤色で始まるとき、赤色の個数は$1+A+D$で、青色の個数は$C+D$である。青で始まる場合も同様。
$B,D$は色の切り替わりの回数なので$|B - D| \le 1$である。そうでない場合は個数は$0$となる。
$B \lt D \; (= B+1)$であるとき、赤青という並びより青赤という並びの方が多いので、赤色で始まって赤色で終わる。
赤で始まるとき赤色のグループの数は$1 + D$であり、青色のグループの数は$B$である。
$n$個のグループに$r$個の玉を分配するとき、それぞれのグループはひとつ以上の玉を含むので、そのような組合せの数は${}\_{(n-r)+r-1}C\_{r-1}$となる。

### 実装

組合せは$O(n^2)$で計算すると間に合わない。

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
ll inv(ll x) { // O(logn)
    assert (0 < x and x < mod);
    ll y = 1;
    for (int i = 0; (1 << i) <= mod - 2; ++ i) {
        if ((mod - 2) & (1 << i)) {
            y = y * x % mod;
        }
        x = x * x % mod;
    }
    return y;
}
ll combination(ll n, ll r) { // O(nlogn), O(1)
    assert (0 <= n and 0 <= r or r <= n);
    static vector<ll> fact(1,1);
    static vector<ll> ifact(1,1);
    if (not (n < fact.size())) {
        int l = fact.size();
        fact.resize(n + 1);
        ifact.resize(n + 1);
        repeat_from (i,l,n+1) {
            fact[i] = fact[i-1] * i % mod;
            ifact[i] = inv(fact[i]);
        }
    }
    r = min(r, n - r);
    return fact[n] * ifact[n-r] % mod * ifact[r] % mod;
}

ll distribute_strict(int n, int r) { // distribute n same things into r distinguishable groups, each group has positive number of things
    assert (n >= r);
    return combination((n-r)+r-1,r-1);
}
ll starts_with_r(int rr, int rb, int bb, int br) {
    if (not (rb == br or rb == br+1)) return 0;
    if (rb == 0 and br == 0) return bb == 0 ? 1 : 0;
    ll r = distribute_strict(1 + rr + br, 1 + br);
    ll b = distribute_strict(    bb + rb,     rb);
    return r * b % mod;
}
int main() {
    int a, b, c, d; cin >> a >> b >> c >> d;
    cout << (starts_with_r(a,b,c,d) + starts_with_r(c,d,a,b)) % mod << endl;
}
```
