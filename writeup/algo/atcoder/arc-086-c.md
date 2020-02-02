---
layout: post
alias: "/blog/2018/01/03/arc-086-c/"
title: "AtCoder Regular Contest 086: C - Not so Diverse"
date: "2018-01-03T23:45:08+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc086/tasks/arc086_a" ]
---

## solution

整数の種類であって書かれたボールの数が少ないものから順に書き換えていく。$O(N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);
    // solve
    map<int, int> cnt;
    for (int a_i : a) cnt[a_i] += 1;
    vector<int> b;
    for (auto it : cnt) b.push_back(it.second);
    sort(ALL(b));
    reverse(ALL(b));
    int result = b.size() <= k ? 0 : accumulate(b.begin() + k, b.end(), 0);
    // output
    printf("%d\n", result);
    return 0;
}
```
