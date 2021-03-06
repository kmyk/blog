---
layout: post
redirect_from:
  - /writeup/algo/etc/hoj-097-003/
  - /blog/2017/07/07/hoj-097-003/
date: "2017-07-07T23:30:07+09:00"
tags: [ "competitive", "writeup", "hoj", "repunit" ]
---

# Hamako Online Judge #097 ukuku09: 003 - repdigit

-   <https://hoj.hamako-ths.ed.jp/onlinejudge/contest/97/problems/3>
-   <https://hoj.hamako-ths.ed.jp/onlinejudge/problems/768>

## solution

`0`がなければ結果の整数は`111...1222...2333...3.........999...9`という形。
ある場合は`111000...0111...1222...2.........`や`222000...0222...2333...3.........`のように必要最小限だけ前に出す。
これらをいい感じに計算すればよい。
repunit $111 \dots 1$や$10^k$は線形の漸化式を持つので桁数の対数で求められる。階乗する部分が一番重くて$O(N + \sum b\_i)$。

## implementation

``` c++
#include <array>
#include <cassert>
#include <cstdio>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <int mod>
int fact(int n) {
    static vector<int> memo(1, 1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i, l, n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
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
int repunit(ll n, int mod) { // O(log n)
    ll y = 0;
    ll x = 1;
    for (ll i = 1; i <= n; i <<= 1) {
        if (n & i) y = (y * powmod(10, i, mod) % mod + x) % mod;
        x = (x * powmod(10, i, mod) % mod + x) % mod;
    }
    return y;
}

constexpr int mod = 1e9+7;
pair<int, int> solve(int n, vector<int> const & a, vector<int> const & b) {
    array<int, 10> cnt = {};
    array<ll, 10> acc = {};
    repeat (i, n) {
        cnt[a[i]] += 1;
        acc[a[i]] += b[i];
    }
    int x = 0;
    int y = 1;
    if (cnt[0]) {
        if (n == 1) return make_pair(0, 1);
        int d = 1;
        while (not cnt[d]) ++ d;
        assert (d <= 9);
        int min_length = mod;
        int min_length_count = 0;
        repeat (i, n) {
            if (a[i] == d and b[i] <= min_length) {
                if (b[i] < min_length) {
                    min_length = b[i];
                    min_length_count = 0;
                }
                min_length_count += 1;
            }
        }
        x = (x *(ll) powmod(10, min_length, mod) + repunit(min_length, mod) *(ll) d % mod) % mod;
        y = y *(ll) min_length_count % mod;
        cnt[d] -= 1;
        acc[d] -= min_length;
    }
    repeat (d, 10) {
        x = (x *(ll) powmod(10, acc[d], mod) + repunit(acc[d], mod) *(ll) d % mod) % mod;
        y = y *(ll) fact<mod>(cnt[d]) % mod;
    }
    return make_pair(x, y);
}

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n), b(n); repeat (i, n) scanf("%d%d", &a[i], &b[i]);
    int x, y; tie(x, y) = solve(n, a, b);
    printf("%d\n", x);
    printf("%d\n", y);
    return 0;
}
```
