---
layout: post
alias: "/blog/2018/04/05/codechef-cook79-cookgame/"
title: "CodeChef Cook79: C. Cooking Game"
date: "2018-04-05T06:48:45+09:00"
tags: [ "competitive", "writeup", "codechef" ]
"target_url": [ "https://www.codechef.com/COOK79/problems/COOKGAME" ]
---

## solution

逆向きに制約を伝播させていって、残る`?`の数の指数が答え。$O(N)$。
$A\_1 = 1$の制約に注意。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

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

constexpr int MOD = 1e9 + 7;
int solve(int n, vector<int> a) {
    REP_R (i, n - 1) {
        if (a[i + 1] >= 2) {
            if (a[i] == -1) {
                a[i] = a[i + 1] - 1;
            } else {
                if (a[i] != a[i + 1] - 1) {
                    return 0;
                }
            }
        }
    }
    if (a[0] == -1) {
        a[0] = 1;
    } else {
        if (a[0] != 1) {
            return 0;
        }
    }
    int k = count(ALL(a), -1);
    return powmod(2, k, MOD);
}

int main() {
    int t; cin >> t;
    while (t --) {
        int n; cin >> n;
        vector<int> a(n); REP (i, n) cin >> a[i];
        cout << solve(n, a) << endl;
    }
    return 0;
}
```
