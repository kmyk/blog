---
layout: post
alias: "/blog/2017/08/25/srm-720-easy/"
date: "2017-08-25T21:47:49+09:00"
title: "TopCoder SRM 720 Div1 Easy: SumProduct"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "combination" ]
---

実質Medium。

## solution

$A, B$の各桁の数字をそれぞれ固定し、そのようなときの残りの埋め方が何通りか考える。基数$d = 10$として$O(d^3 (\mathrm{blank}\_1 + \mathrm{blank}\_2) + d^2(\mathrm{blank}\_1 \mathrm{blank}\_2)^2)$とか。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;

class SumProduct { public: int findSum(vector<int> amount, int blank1, int blank2); };

vector<vector<int> > calc_choose(int n, int mod) { // O(n^2)
    vector<vector<int> > dp(n + 1);
    dp[0].assign(1, 1);
    repeat (i, n) {
        dp[i + 1].resize(i + 2);
        repeat (j, i + 2) {
            if (j - 1 >= 0) dp[i + 1][j] += dp[i][j - 1];
            if (j != i + 1) dp[i + 1][j] += dp[i][j];
            dp[i + 1][j] %= mod;
        }
    }
    return dp;
}
vector<int> calc_pow(int base, int n, int mod) {
    vector<int> dp(n + 1);
    dp[0] = 1;
    repeat (i, n) {
        dp[i + 1] = dp[i] *(ll) base % mod;
    }
    return dp;
}

constexpr int mod = 1e9+7;
int SumProduct::findSum(vector<int> amount, int blank1, int blank2) {
    auto choose = calc_choose(blank1 + blank2, mod);
    auto pow_10 = calc_pow(10, max(blank1, blank2), mod);
    ll result = 0;
    repeat (d_i, 10) repeat (d_j, 10) {
        -- amount[d_i];
        -- amount[d_j];
        if (amount[d_i] >= 0 and amount[d_j] >= 0) {
            const int blank = blank1 + blank2 - 2;
            vector<int> cur(blank + 1);
            vector<int> prv(blank + 1);
            cur[0] = 1;
            repeat (d, 10) {
                cur.swap(prv);
                repeat (k, blank + 1) {
                    ll acc = 0;
                    repeat (delta, min(amount[d], k) + 1) {
                        acc += choose[k][delta] *(ll) prv[k - delta] % mod;
                    }
                    cur[k] = acc % mod;
                }
            }
            repeat (i, blank1) repeat (j, blank2) {
                result += cur[blank]
                    *(ll) d_i % mod * pow_10[i] % mod
                    *(ll) d_j % mod * pow_10[j] % mod;
            }
        }
        ++ amount[d_j];
        ++ amount[d_i];
    }
    return result % mod;
}
```
