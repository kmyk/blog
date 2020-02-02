---
layout: post
alias: "/blog/2017/02/22/hackerrank-university-codesprint-2-sherlocks-array-merging-algorithm/"
date: "2017-02-22T23:44:21+09:00"
title: "HackerRank University CodeSprint 2: Sherlock's Array Merging Algorithm"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "university-codesprint", "dp" ]
"target_url": [ "https://www.hackerrank.com/contests/university-codesprint-2/challenges/sherlocks-array-merging-algorithm" ]
---

## problem

$1, 2, \dots, n$の順列$M$が与えられる。問題文中の疑似言語で指示されたアルゴリズムで処理したとき、結果がこの$M$になるような入力$V$の種類数を答えよ。

## solution

DP。$O(N^3)$。

ただし簡単な定数倍高速化が必要だった。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int mod = 1e9+7;
ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (y >= 0);
    x %= p; if (x < 0) x += p;
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
int fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
int permute(int n, int r) {
    if (n < r) return 0;
    return fact(n) *(ll) inv(fact(n-r), mod) % mod;
}
const int N_MAX = 1200;
int permute_table_rev[N_MAX+1][N_MAX+1]; // important for optimization
int main() {
    repeat (i,N_MAX+1) repeat (j,N_MAX+1) permute_table_rev[j][i] = permute(i, j);
    int n; cin >> n;
    vector<int> m(n); repeat (i,n) cin >> m[i];
    vector<vector<int> > dp = vectors(n+1, n+1, int());
    dp[0][n] = 1;
    repeat (r,n+1) {
        repeat_reverse (l,r) {
            if (l+1 < r and m[l] > m[l+1]) break;
            ll acc = 0;
            repeat_from (k,r-l,n+1) {
                acc += dp[l][k] *(ll) (l == 0 ? 1 : permute_table_rev[r-l][k]) % mod;
            }
            dp[r][r-l] = acc % mod;
        }
    }
    ll ans = 0;
    repeat (j,n+1) ans += dp[n][j];
    cout << ans % mod << endl;
    return 0;
}
```
