---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-092-c/
  - /blog/2018/04/05/arc-092-c/
date: "2018-04-05T04:30:04+09:00"
tags: [ "competitive", "writeup", "arc", "greedy", "bipartite-matching" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc092/tasks/arc092_a" ]
---

# AtCoder Regular Contest 092: C - 2D Plane 2N Points

## solution

二部グラフの最大マッチングを求めたくなるが、貪欲で十分。$O(N \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<pair<int, int> > a(n); REP (i, n) scanf("%d%d", &a[i].first, &a[i].second);
    vector<pair<int, int> > b(n); REP (i, n) scanf("%d%d", &b[i].first, &b[i].second);

    // solve
    sort(ALL(a));
    sort(ALL(b));
    vector<int> by;
    int result = 0;
    while (not a.empty()) {
        int ax, ay; tie(ax, ay) = a.back();
        a.pop_back();
        while (not b.empty() and ax < b.back().first) {
            by.push_back(b.back().second);
            b.pop_back();
        }
        int j = -1;
        REP (i, by.size()) if (ay < by[i]) {
            if (j == -1 or by[i] < by[j]) {
                j = i;
            }
        }
        if (j != -1) {
            by.erase(by.begin() + j);
            result += 1;
        }
    }

    // output
    printf("%d\n", result);
    return 0;
}
```
