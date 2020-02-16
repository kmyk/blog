---
layout: post
alias: "/blog/2017/12/31/hackerrank-world-codesprint-12-the-salesman/"
date: "2017-12-31T16:26:19+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-12/challenges/the-salesman" ]
---

# HackerRank World CodeSprint 12: The Salesman

## solution

最大値と最小値を求めてその差。各ケース$O(N)$。

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;
int main() {
    int t; cin >> t;
    while (t --) {
        int n; cin >> n;
        int min_x = INT_MAX;
        int max_x = INT_MIN;
        while (n --) {
            int x; cin >> x;
            min_x = min(min_x, x);
            max_x = max(max_x, x);
        }
        cout << max_x - min_x << endl;
    }
    return 0;
}
```
