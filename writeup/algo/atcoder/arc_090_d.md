---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-090-d/
  - /blog/2018/04/09/arc-090-d/
date: "2018-04-09T23:19:38+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc090/tasks/arc090_b" ]
---

# AtCoder Regular Contest 090: D - People on a Line

## solution

情報$(L\_i, R\_i, D\_i)$を無向辺と見て、各連結成分ごとに矛盾がないか確認。
$x\_i \in [0, 10^9]$の制約は(一見罠っぽいが)無視してよいため、適当なものを$0$と置いて確定させていく。$O(NM)$。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<pair<int, int> > > g(n);
    REP (i, m) {
        int l, r, d; scanf("%d%d%d", &l, &r, &d);
        -- l;
        -- r;
        g[l].emplace_back(r, + d);
        g[r].emplace_back(l, - d);
    }
    // solve
    vector<ll> x(n, LLONG_MAX);
    function<void (int)> go = [&](int i) {
        for (auto edge : g[i]) {
            int j, dist; tie(j, dist) = edge;
            if (x[j] == LLONG_MAX) {
                x[j] = x[i] + dist;
                go(j);
            }
            if (x[j] != x[i] + dist) {
                throw (void *)nullptr;
            }
        }
    };
    bool result = true;
    try {
        REP (i, n) {
            if (x[i] == LLONG_MAX) {
                x[i] = 0;
                go(i);
            }
        }
    } catch (void *) {
        result = false;
    }
    // output
    printf("%s\n", result ? "Yes" : "No");
    return 0;
}
```
