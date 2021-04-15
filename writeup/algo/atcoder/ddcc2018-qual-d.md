---
redirect_from:
  - /writeup/algo/atcoder/ddcc2018-qual-d/
layout: post
date: 2018-11-24T02:04:51+09:00
tags: [ "competitive", "writeup", "atcoder", "ddcc", "chinese-remainder-theorem", "digits-sum" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2019-qual/tasks/ddcc2018_qual_d" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2019 予選: D - チップ・ストーリー　～黄金編～

## 解法

### 概要

$$9$$ の倍数判定の一般化である「$$n$$ の $$i$$ 進数での数字和は $$n \bmod (i - 1)$$ に等しい」に気付く。
あとは中国人剰余定理。
一般的なCRTがなくても、互いに素になるようにいくつか数字を選んでやれば十分のはず。
$$O(\log n)$$ ぐらい。

## メモ

-   CRTはここを見ながら書いた: [数学 - 中国人剰余定理 - ₍₍ (ง ˘ω˘ )ว ⁾⁾ &lt; 暗号楽しいです](http://elliptic-shiho.hatenablog.com/entry/2016/04/03/020117)
-   倍数判定のあたりに詳しくなかったので別にまとめた: <https://kimiyuki.net/blog/2018/11/23/division-by-hand/>

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

tuple<ll, ll, ll> extgcd(ll a, ll b) {
    ll x = 0, y = 1;
    for (ll u = 1, v = 0; a; ) {
        ll q = b / a;
        x -= q * u; swap(x, u);
        y -= q * v; swap(y, v);
        b -= q * a; swap(b, a);
    }
    return make_tuple(x, y, b);
}

ll multmod(ll a, ll b, ll m) {
    a = (a % m + m) % m;
    b = (b % m + m) % m;
    ll c = 0;
    REP (i, 63) {
        if (b & (1ll << i)) {
            c += a;
            if (c > m) c -= m;
        }
        a *= 2;
        if (a > m) a -= m;
    }
    return c;
}

pair<ll, ll> crt(pair<ll, ll> eqn1, pair<ll, ll> eqn2) {
    ll x1, m1; tie(x1, m1) = eqn1;
    ll x2, m2; tie(x2, m2) = eqn2;
    if (m1 == 0 or m2 == 0) return make_pair(0ll, 0ll);
    assert (1 <= m1 and 1 <= m2);
    ll m1_inv, d; tie(m1_inv, ignore, d) = extgcd(m1, m2);
    if ((x1 - x2) % d) return make_pair(0ll, 0ll);
    ll m = m1 * m2 / d;
    ll x = x1 + multmod(multmod(m1 / d, x2 - x1, m), m1_inv, m);
    return make_pair((x % m + m) % m, m);
}

int get_a_i(ll n, int i) {
    int a_i = 0;
    for (; n; n /= i) {
        a_i += n % i;
    }
    return a_i;
}

ll solve(array<int, 31> const & a) {
    ll n = 0, m = 1;
    REP3 (i, 2, 31) {
        tie(n, m) = crt(make_pair(n, m), make_pair(a[i] % (i - 1), i - 1));
        if (m > 1e12) break;
    }
    if (n == 0 or n > 1e12) return -1;
    REP3 (i, 2, 31) {
        if (get_a_i(n, i) != a[i]) return -1;
    }
    return n;
}

int main() {
    array<int, 31> a;
    REP3 (i, 2, 31) cin >> a[i];
    ll n = solve(a);
    if (n == -1) {
        cout << "invalid" << endl;
    } else {
        cout << n << endl;
    }
    return 0;
}
```
