---
layout: post
alias: "/blog/2018/03/18/srm-731-med/"
date: "2018-03-18T03:19:44+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "tree" ]
---

# TopCoder SRM 731 Medium. RndSubTree

## problem

無限の深さの完全二分木が与えられる。
$k$個の頂点をある手順で赤く塗る。
赤い頂点を結ぶ${}\_kC\_2$個の辺の長さの総和の期待値を答えよ。

## solution

DP。$k$のときの長さの総和の期待値(答え) $f(k)$と、 $k$のときの赤い頂点の深さの平均の期待値$g(k)$を求める。
根で止まるひとつを除いた$k - 1$個がどう左右に振り分けられるかを総当たり。$O(k)$。

## memo

方針は自明なのにバグがまったくとれず。実装力ほしい

## implementation

``` c++
#include <bits/stdc++.h>
#include <tuple>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
typedef long long ll;
using namespace std;
class RndSubTree { public: int count(int k); };

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
ll modinv(ll x, ll p) {
    assert (x % p != 0);
    return powmod(x, p - 2, p);
}
template <int32_t MOD>
int32_t fact(int n) {
    static vector<int32_t> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(int64_t) memo.size() % MOD);
    }
    return memo[n];
}
template <int32_t PRIME>
int32_t inv_fact(int n) {
    static vector<int32_t> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(int64_t) modinv(memo.size(), PRIME) % PRIME);
    }
    return memo[n];
}
template <int MOD>
int choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) *(ll) inv_fact<MOD>(n - r) % MOD *(ll) inv_fact<MOD>(r) % MOD;
}

constexpr int MOD = 1e9 + 7;
pair<ll, ll> addpq(pair<ll, ll> r1, pair<ll, ll> r2) {
    ll p1, q1; tie(p1, q1) = r1;
    ll p2, q2; tie(p2, q2) = r2;
    ll p = (p1 * q2 % MOD + p2 * q1 % MOD) % MOD;
    ll q = q1 * q2 % MOD;
    return make_pair(p, q);
}
pair<ll, ll> mulpq(pair<ll, ll> r1, pair<ll, ll> r2) {
    ll p1, q1; tie(p1, q1) = r1;
    ll p2, q2; tie(p2, q2) = r2;
    ll p = p1 * p2 % MOD;
    ll q = q1 * q2 % MOD;
    return make_pair(p, q);
}
pair<pair<ll, ll>, pair<ll, ll> > recur(int k) {
    if (k == 0) {
        return make_pair(make_pair(0, 1), make_pair(0, 1));
    } else if (k == 1) {
        return make_pair(make_pair(0, 1), make_pair(1, 1));
    } else {
        static map<int, pair<pair<ll, ll>, pair<ll, ll> > > memo;
        if (memo.count(k)) return memo[k];
        pair<ll, ll> acc = { 0, 1 };
        pair<ll, ll> acc_up = { 0, 1 };
        ll den = powmod(2, k - 1, MOD);
        REP (k1, k) {
            int k2 = (k - 1) - k1;
            ll num = choose<MOD>(k1 + k2, k1);
            pair<ll, ll> a1, up1; tie(a1, up1) = recur(k1);
            pair<ll, ll> a2, up2; tie(a2, up2) = recur(k2);
            pair<ll, ll> a = { 0, 1 };
            a = addpq(a, a1);
            a = addpq(a, a2);
            a = addpq(a, mulpq(up1, make_pair(k1, 1)));
            a = addpq(a, mulpq(up2, make_pair(k2, 1)));
            a = addpq(a, mulpq(addpq(up1, up2), make_pair(k1 *(ll) k2 % MOD, 1)));
            a = mulpq(a, make_pair(num, den));
            acc = addpq(acc, a);
            pair<ll, ll> up = { 0, 1 };
            up = addpq(up, mulpq(up1, make_pair(k1, 1)));
            up = addpq(up, mulpq(up2, make_pair(k2, 1)));
            up = mulpq(up, make_pair(1, k));
            up = addpq(up, make_pair(1, 1));
            up = mulpq(up, make_pair(num, den));
            acc_up = addpq(acc_up, up);
        }
        return memo[k] = make_pair(acc, acc_up);
    }
}

int RndSubTree::count(int k) {
    ll p, q; tie(p, q) = recur(k).first;
    return p * modinv(q, MOD) % MOD;
}
```
