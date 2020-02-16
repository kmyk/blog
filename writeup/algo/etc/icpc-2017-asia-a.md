---
layout: post
alias: "/blog/2017/12/19/icpc-2017-asia-a/"
date: "2017-12-19T03:48:50+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia", "dp" ]
---

# AOJ 1378 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: A. Secret of Chocolate Poles

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1378>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=A>

## problem

厚み$1, k$の黒いチョコレートと厚み$1$の白いチョコレートがある。
一番上と一番下が黒色であるように白黒のチョコレートを交互に積み高さ$l$以下にするとき、そのような積み方は何通りか。。

## solution

DP。$O(l)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
int main() {
    int l, k; scanf("%d%d", &l, &k);
    vector<ll> dp(l + 1);
    REP (i, l + 1) {
        if (i == 1 or i == k) dp[i] += 1;
        if (i - 2 >= 0) dp[i] += dp[i - 2];
        if (i - k - 1 >= 0) dp[i] += dp[i - k - 1];
    }
    ll result = accumulate(ALL(dp), 0ll);
    printf("%lld\n", result);
    return 0;
}
```
