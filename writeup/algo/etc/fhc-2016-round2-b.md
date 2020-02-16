---
layout: post
alias: "/blog/2016/01/24/fhc-2016-round2-b/"
date: 2016-01-24T06:02:41+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "expected-value", "dp" ]
---

# Facebook Hacker Cup 2016 Round 2 Carnival Coins

## [Carnival Coins](https://www.facebook.com/hackercup/problem/1627951250755660/)

### 問題

コインが$n$枚与えられる。
適当に$i$枚コインをまとめて投げてよい。投げたコインは消費される。
コインは一様な確率$p$で表がでる。
コインを投げて表が$k$枚以上でるたびに、景品が$1$つ貰える。
$n$枚を最適に投げたとき、貰える景品の数の期待値を答えよ。

### 解法

普通にdp。

まず$i$個コインを投げたときに$k$個以上表になる確率をdpして、これを元に$n$個コインを使ったときに貰える景品の数の期待値をdp。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
void solve() {
    int n, k; double p; cin >> n >> k >> p;
    vector<double> q(n+1); {
        vector<double> cur(k+1), prv;
        cur[0] = 1;
        repeat (i,n) {
            prv = cur;
            cur[0] = prv[0]*(1-p);
            repeat_from (j,1,k) cur[j] = prv[j]*(1-p) + prv[j-1]*p;
            cur[k] = prv[k] + prv[k-1]*p;
            q[i+1] = cur[k];
        }
    }
    vector<double> dp(n+1);
    repeat (i,n+1) {
        repeat (j,i+1) {
            dp[i] = max(dp[i], dp[i-j] + q[j]);
        }
    }
    printf("%.12lf\n", dp[n]);
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": ";
        solve();
    }
    return 0;
}
```
