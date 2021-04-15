---
redirect_from:
  - /writeup/algo/codeforces/1007-a/
layout: post
date: 2018-07-27T05:50:44+09:00
tags: [ "competitive", "writeup", "codeforces", "greedy" ]
"target_url": [ "http://codeforces.com/contest/1007/problem/A" ]
---

# Codeforces Round #497 (Div. 1): A. Reorder the Array

## problem

数列$a$が与えられる。適当に並び換えて$b$としたとき$a_i \lt b_i$であるような位置$i$の数を最大化したい。
その最大値はいくつか。

## solution

貪欲。個数だけ数えていい感じにずらす。$O(N \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n);
    REP (i, n) scanf("%d", &a[i]);

    // solve
    map<int, int> b;
    for (int a_i : a) {
        b[a_i] += 1;
    }
    int answer = 0;
    int place = 0;
    for (auto it : b) {
        int cnt = it.second;
        int delta = min(place, cnt);
        answer += delta;
        place += cnt - delta;
    }

    // output
    printf("%d\n", answer);
    return 0;
}
```
