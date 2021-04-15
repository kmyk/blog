---
layout: post
redirect_from:
  - /writeup/algo/csacademy/72-b/
  - /writeup/algo/cs-academy/72-b/
  - /blog/2018/03/08/csa-72-b/
date: "2018-03-08T12:04:31+09:00"
tags: [ "competitive", "writeup", "csa", "dp" ]
"target_url": [ "https://csacademy.com/contest/round-72/task/circle-kingdom/statement/" ]
---

# CS Academy Round #72. Circle Kingdom

## solution

首都にした場合の費用をそれぞれについて$O(N)$で求める。$O(N^2)$。

費用を$\sum c\_i$から引くことで右方向か左方向の一方のみ舐めれば十分。
一言で言うならDPに分類されると思う。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> c(n); REP (i, n) scanf("%d", &c[i]);

    // solve
    int result = -1;
    int result_cost = INT_MAX;
    int sum_c = accumulate(ALL(c), 0);
    REP (i, n) {
        int cost = 0;
        int acc = 0;
        REP3 (j, i, n) {
            acc += c[j];
            chmax(cost, min(acc, sum_c - acc));
        }
        REP (j, i) {
            acc += c[j];
            chmax(cost, min(acc, sum_c - acc));
        }
        if (cost < result_cost) {
            result_cost = cost;
            result = i;
        }
    }

    // output
    printf("%d\n", result + 1);
    return 0;
}
```
